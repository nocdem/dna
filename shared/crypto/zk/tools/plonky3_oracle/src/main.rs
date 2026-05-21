//! DNAC-ZK Plonky3 reference oracle.
//!
//! Generates deterministic test vectors for primitives in
//! `shared/crypto/zk/`. C-side ctests load these JSON files and assert
//! byte-identity with their own outputs.
//!
//! Plonky3 is pinned to commit 82cfad73 (2026-05-20). See Cargo.toml.
//!
//! Sprint 1.1 scope: field_ops only. Other subcommands are stubs that
//! return "not implemented in Sprint 1.1" and exit cleanly.
//!
//! Usage:
//!   cargo run --release -- dump-field-ops --out ../vectors/field_ops.json
//!   cargo run --release -- dump-all --out-dir ../vectors/
//!
//! Determinism:
//!   - Test inputs are deterministic functions of (operation_id, case_index).
//!   - No RNG / no time-based input — same binary always emits same JSON.
//!   - `cargo build --release --frozen` with committed Cargo.lock ensures
//!     bit-reproducible binary across machines.

use clap::{Parser, Subcommand};
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

/// Type alias for Goldilocks² extension field (degree-2 binomial extension).
type GoldFp2 = BinomialExtensionField<Goldilocks, 2>;

// ============================================================================
// Constants
// ============================================================================

/// Goldilocks prime p = 2^64 - 2^32 + 1 = 18446744069414584321.
const GOLDILOCKS_P: u64 = 0xFFFFFFFF_00000001;

/// Number of test cases per arithmetic operation.
const CASES_PER_OP: usize = 1024;

/// Plonky3 commit hash pinned in design doc (for embedding in JSON metadata).
const PLONKY3_COMMIT: &str = "82cfad73cd734d37a0d51953094f970c531817ec";

/// Oracle output format version. Bump when format changes.
const ORACLE_FORMAT_VERSION: &str = "1";

// ============================================================================
// JSON output schema
// ============================================================================

#[derive(Serialize)]
struct VectorFile {
    format_version: &'static str,
    plonky3_commit: &'static str,
    field_p: String,
    operations: Operations,
}

#[derive(Serialize, Default)]
struct Operations {
    add: Vec<BinaryCase>,
    sub: Vec<BinaryCase>,
    mul: Vec<BinaryCase>,
    neg: Vec<UnaryCase>,
    sqr: Vec<UnaryCase>,
    inv: Vec<UnaryCase>,
    pow: Vec<PowCase>,
}

#[derive(Serialize)]
struct BinaryCase {
    a: String, // u64 in decimal, ASCII-safe across languages
    b: String,
    out: String,
}

#[derive(Serialize)]
struct UnaryCase {
    a: String,
    out: String,
}

#[derive(Serialize)]
struct PowCase {
    a: String,
    k: String, // exponent u64 decimal
    out: String,
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "plonky3_oracle", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dump base-field operation test vectors.
    DumpFieldOps {
        /// Output JSON file path.
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump Goldilocks² extension field test vectors (Sprint 1.3).
    DumpFieldExt {
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump Merkle SMT test vectors (Sprint 1.4).
    DumpMerkle {
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump Fiat-Shamir transcript test vectors (Sprint 1.5).
    DumpTranscript {
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump in-AIR Keccak test vectors (retired post Option B).
    DumpKeccakAir {
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump TWO_ADIC_GENERATORS[0..=32] (Sub-sprint 2.1).
    DumpTwoAdicGens {
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump FRI arity-2 fold test vectors (Sub-sprint 2.1).
    DumpFriFold {
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump FRI multi-layer commit phase test vectors (Sub-sprint 2.2).
    DumpFriCommit {
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump all (runs all subcommands; ones not yet implemented are skipped).
    DumpAll {
        #[arg(long)]
        out_dir: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::DumpFieldOps { out } => dump_field_ops(&out)?,
        Cmd::DumpFieldExt { out } => dump_field_ext(&out)?,
        Cmd::DumpMerkle { out } => dump_merkle(&out)?,
        Cmd::DumpTranscript { out } => dump_transcript(&out)?,
        Cmd::DumpKeccakAir { out: _ } => {
            eprintln!("dump-keccak-air: retired post Option B revision 2026-05-21");
        }
        Cmd::DumpTwoAdicGens { out } => dump_two_adic_gens(&out)?,
        Cmd::DumpFriFold { out } => dump_fri_fold(&out)?,
        Cmd::DumpFriCommit { out } => dump_fri_commit(&out)?,
        Cmd::DumpAll { out_dir } => {
            std::fs::create_dir_all(&out_dir)?;
            dump_field_ops(&out_dir.join("field_ops.json"))?;
            dump_field_ext(&out_dir.join("field_ext.json"))?;
            dump_merkle(&out_dir.join("merkle.json"))?;
            dump_transcript(&out_dir.join("transcript.json"))?;
            dump_two_adic_gens(&out_dir.join("two_adic_gens.json"))?;
            dump_fri_fold(&out_dir.join("fri_fold.json"))?;
            dump_fri_commit(&out_dir.join("fri_commit.json"))?;
        }
    }
    Ok(())
}

// ============================================================================
// Field-ops dump (Sprint 1.1)
// ============================================================================

/// Generate a deterministic u64 from (op_id, case_index).
/// Avoids RNG state; same op_id + case_index always yields same value.
fn deterministic_u64(op_id: u32, case_index: u32) -> u64 {
    // Linear-congruential mix; not cryptographic, just deterministic.
    let seed: u64 = 0xD9AC_0000_0000_0000
        | ((op_id as u64) << 32)
        | (case_index as u64);
    // One round of SplitMix64-style avalanche.
    let mut x = seed;
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Canonicalize a u64 into [0, p) for use as a Goldilocks input.
fn canonical(x: u64) -> u64 {
    if x >= GOLDILOCKS_P {
        x - GOLDILOCKS_P
    } else {
        x
    }
}

/// Convert a Goldilocks element to canonical u64.
fn to_u64(g: Goldilocks) -> u64 {
    g.as_canonical_u64()
}

/// Test-case generator for binary ops.
fn binary_cases(op_id: u32, n: usize, op: impl Fn(Goldilocks, Goldilocks) -> Goldilocks) -> Vec<BinaryCase> {
    let mut out = Vec::with_capacity(n + 6);
    // Edge cases first.
    let edges = [
        (0u64, 0u64),
        (1, 1),
        (0, GOLDILOCKS_P - 1),
        (GOLDILOCKS_P - 1, GOLDILOCKS_P - 1),
        (1, GOLDILOCKS_P - 1),
        (2, GOLDILOCKS_P - 2),
    ];
    for (a, b) in edges {
        let ga = Goldilocks::from_u64(a);
        let gb = Goldilocks::from_u64(b);
        out.push(BinaryCase {
            a: a.to_string(),
            b: b.to_string(),
            out: to_u64(op(ga, gb)).to_string(),
        });
    }
    // Deterministic body.
    for i in 0..(n as u32) {
        let a = canonical(deterministic_u64(op_id, i * 2));
        let b = canonical(deterministic_u64(op_id, i * 2 + 1));
        let ga = Goldilocks::from_u64(a);
        let gb = Goldilocks::from_u64(b);
        out.push(BinaryCase {
            a: a.to_string(),
            b: b.to_string(),
            out: to_u64(op(ga, gb)).to_string(),
        });
    }
    out
}

/// Test-case generator for unary ops; allows skipping zero (for inv).
fn unary_cases(op_id: u32, n: usize, skip_zero: bool, op: impl Fn(Goldilocks) -> Goldilocks) -> Vec<UnaryCase> {
    let mut out = Vec::with_capacity(n + 4);
    let edges = if skip_zero {
        vec![1u64, GOLDILOCKS_P - 1, 2, GOLDILOCKS_P - 2]
    } else {
        vec![0u64, 1, GOLDILOCKS_P - 1, 2]
    };
    for a in edges {
        let ga = Goldilocks::from_u64(a);
        out.push(UnaryCase {
            a: a.to_string(),
            out: to_u64(op(ga)).to_string(),
        });
    }
    for i in 0..(n as u32) {
        let mut a = canonical(deterministic_u64(op_id, i));
        if skip_zero && a == 0 {
            a = 1;
        }
        let ga = Goldilocks::from_u64(a);
        out.push(UnaryCase {
            a: a.to_string(),
            out: to_u64(op(ga)).to_string(),
        });
    }
    out
}

fn pow_cases(op_id: u32, n: usize) -> Vec<PowCase> {
    let mut out = Vec::with_capacity(n);
    // Edge cases.
    let edges = [
        (0u64, 0u64), // 0^0 — Plonky3 convention check
        (0, 1),       // 0^1 = 0
        (1, 0),       // 1^0 = 1
        (1, 5),
        (2, 64),
        (3, GOLDILOCKS_P - 2), // a^(p-2) == a^-1 (Fermat)
    ];
    for (a, k) in edges {
        let ga = Goldilocks::from_u64(a);
        let result = ga.exp_u64(k);
        out.push(PowCase {
            a: a.to_string(),
            k: k.to_string(),
            out: to_u64(result).to_string(),
        });
    }
    for i in 0..(n as u32) {
        let a = canonical(deterministic_u64(op_id, i * 2));
        let k = deterministic_u64(op_id, i * 2 + 1) & 0xFFFF; // bound exponent
        let ga = Goldilocks::from_u64(a);
        let result = ga.exp_u64(k);
        out.push(PowCase {
            a: a.to_string(),
            k: k.to_string(),
            out: to_u64(result).to_string(),
        });
    }
    out
}

// ============================================================================
// FRI multi-layer commit phase dump (Sub-sprint 2.2)
//
// DNAC-internal FRI commit phase:
//   Input:  initial_values (2^k Goldilocks² elements on coset of size 2^k)
//           cap_height_log  — stop folding when layer_log_size ≤ cap_height_log
//           transcript already initialized (chain_id + init params absorbed)
//
//   Repeat while layer_log_size > cap_height_log:
//     1. Serialize each Goldilocks² value to 16 bytes (a0_BE || a1_BE).
//     2. Hash each as a Merkle leaf (DNAC_RP_LEAF\0 || idx_BE || bytes).
//     3. Compute Merkle root over 2^layer_log_size leaves.
//     4. transcript_absorb(root)  — root flows into Fiat-Shamir state.
//     5. beta = transcript_challenge_fp2()
//     6. Fold layer using fri_fold_arity2(layer, halve_inv_powers, beta).
//     7. layer_log_size -= 1
//
//   Output: list of layer Merkle roots + final_values + intermediate state.
// ============================================================================

/// Serialize a Goldilocks² element to 16 bytes (a_BE_u64 || b_BE_u64).
fn fp2_to_bytes(x: GoldFp2) -> [u8; 16] {
    let coeffs: &[Goldilocks] =
        <GoldFp2 as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&x);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&coeffs[0].as_canonical_u64().to_be_bytes());
    out[8..16].copy_from_slice(&coeffs[1].as_canonical_u64().to_be_bytes());
    out
}

/// Compute Merkle leaf hash for an Fp2 element at index i (using same domain
/// separator as merkle_smt module).
fn fri_leaf_hash(index: u32, val: GoldFp2) -> [u8; 64] {
    let val_bytes = fp2_to_bytes(val);
    merkle_hash_leaf(index, &val_bytes)
}

/// Build Merkle root over a flat array of layer values.
/// Tree depth = log2(values.len()) (must be a power of 2).
fn fri_layer_root(values: &[GoldFp2]) -> [u8; 64] {
    let n = values.len();
    assert!(n.is_power_of_two(), "layer size must be power of 2");
    let depth = n.trailing_zeros();
    let leaves: Vec<[u8; 64]> =
        values.iter().enumerate().map(|(i, v)| fri_leaf_hash(i as u32, *v)).collect();
    merkle_compute_root(&leaves, depth)
}

#[derive(Serialize)]
struct FriCommitLayer {
    layer_index: u32,
    layer_log_size: u32,
    /// Merkle root over this layer's values (before fold).
    merkle_root_hex: String,
    /// beta challenge derived from transcript after absorbing the root.
    beta: [String; 2],
    /// halve_inv_powers[i] = (g^{-i} / 2) for i in 0..layer_log_size/2,
    /// where g = two_adic_generator(layer_log_size) (size-2H coset).
    /// Provided so the C side can cross-check without independently computing g.
    halve_inv_powers: Vec<String>,
    /// Layer values AFTER fold (size = current_size / 2).
    /// Included for granular C-side debugging. Production fri_commit does NOT
    /// retain all layer values.
    folded_values: Vec<[String; 2]>,
}

#[derive(Serialize)]
struct FriCommitCase {
    name: String,
    initial_log_size: u32,
    cap_height_log: u32,
    transcript_init: TranscriptInit,
    initial_values: Vec<[String; 2]>,
    /// Transcript state AFTER init, BEFORE entering FRI commit loop.
    /// C side initializes its transcript identically; should match.
    transcript_state_pre_loop_hex: String,
    /// Counter value pre-loop (should be 0 — but recorded for completeness).
    transcript_counter_pre_loop: u32,
    layers: Vec<FriCommitLayer>,
    /// Final layer values (size = 2^cap_height_log).
    final_layer_values: Vec<[String; 2]>,
    /// Transcript state AFTER full commit phase.
    transcript_state_post_loop_hex: String,
    transcript_counter_post_loop: u32,
}

#[derive(Serialize)]
struct FriCommitFile {
    format_version: &'static str,
    plonky3_commit: &'static str,
    convention: &'static str,
    cases: Vec<FriCommitCase>,
}

fn run_fri_commit_oracle(
    initial_values: &[GoldFp2],
    cap_height_log: u32,
    chain_id: &[u8; 32],
    block_height: u64,
    tx_index: u32,
    public_input: &[u8],
) -> FriCommitCase {
    let initial_log_size = initial_values.len().trailing_zeros();
    assert!(initial_values.len().is_power_of_two());

    let mut transcript = OracleTranscript::init(chain_id, block_height, tx_index, public_input);
    let transcript_state_pre_loop_hex = to_hex(&transcript.state);
    let transcript_counter_pre_loop = transcript.counter;

    let mut layer: Vec<GoldFp2> = initial_values.to_vec();
    let mut layers_out: Vec<FriCommitLayer> = Vec::new();
    let mut current_log_size = initial_log_size;
    let mut layer_index: u32 = 0;

    while current_log_size > cap_height_log {
        let layer_size = 1usize << current_log_size;
        assert_eq!(layer.len(), layer_size);

        // 1-3. Merkle root over current layer.
        let root = fri_layer_root(&layer);

        // 4. Absorb root into transcript.
        transcript.absorb(&root);

        // 5. Derive beta.
        let (b0, b1) = transcript.challenge_fp2();
        let beta = mk_fp2(b0, b1);

        // 6. Compute halve_inv_powers and fold.
        let h = layer_size / 2;
        let g = Goldilocks::two_adic_generator(current_log_size as usize);
        let g_inv = g.inverse();
        let half = Goldilocks::from_u64(2).inverse();
        let mut acc = half;
        let mut halve_inv_powers_g: Vec<Goldilocks> = Vec::with_capacity(h);
        for _ in 0..h {
            halve_inv_powers_g.push(acc);
            acc *= g_inv;
        }
        let new_layer = fri_fold_arity2_oracle(&layer, beta, h);

        layers_out.push(FriCommitLayer {
            layer_index,
            layer_log_size: current_log_size,
            merkle_root_hex: to_hex(&root),
            beta: [b0.to_string(), b1.to_string()],
            halve_inv_powers: halve_inv_powers_g
                .iter()
                .map(|x| x.as_canonical_u64().to_string())
                .collect(),
            folded_values: new_layer.iter().map(|v| fp2_to_pair(*v)).collect(),
        });

        layer = new_layer;
        current_log_size -= 1;
        layer_index += 1;
    }

    let transcript_state_post_loop_hex = to_hex(&transcript.state);
    let transcript_counter_post_loop = transcript.counter;

    FriCommitCase {
        name: String::new(), // caller fills
        initial_log_size,
        cap_height_log,
        transcript_init: TranscriptInit {
            chain_id_hex: to_hex(chain_id),
            block_height,
            tx_index,
            public_input_hex: to_hex(public_input),
            initial_state_hex: transcript_state_pre_loop_hex.clone(),
        },
        initial_values: initial_values.iter().map(|v| fp2_to_pair(*v)).collect(),
        transcript_state_pre_loop_hex,
        transcript_counter_pre_loop,
        layers: layers_out,
        final_layer_values: layer.iter().map(|v| fp2_to_pair(*v)).collect(),
        transcript_state_post_loop_hex,
        transcript_counter_post_loop,
    }
}

fn dump_fri_commit(out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = Vec::new();

    let configurations: &[(&str, u32, u32, u32)] = &[
        // (name, initial_log_size, cap_height_log, seed)
        ("small_8_to_2",  8,  2, 1000),
        ("medium_10_to_2",10, 2, 1001),
        ("medium_10_to_4",10, 4, 1002),
        ("large_12_to_3", 12, 3, 1003),
        ("tiny_4_to_1",   4,  1, 1004),
    ];

    for &(name, initial_log_size, cap_height_log, seed) in configurations {
        let n = 1usize << initial_log_size;
        let mut initial_values: Vec<GoldFp2> = Vec::with_capacity(n);
        for i in 0..n {
            let a0 = canonical(deterministic_u64(seed, i as u32 * 2));
            let a1 = canonical(deterministic_u64(seed, i as u32 * 2 + 1));
            initial_values.push(mk_fp2(a0, a1));
        }
        let mut chain_id = [0u8; 32];
        for (i, b) in chain_id.iter_mut().enumerate() {
            *b = (deterministic_u64(seed + 100, i as u32) & 0xff) as u8;
        }
        let block_height = (seed as u64) * 1000;
        let tx_index = seed % 16;
        let public_input = format!("FRI_COMMIT_{}", name).into_bytes();

        let mut case = run_fri_commit_oracle(
            &initial_values,
            cap_height_log,
            &chain_id,
            block_height,
            tx_index,
            &public_input,
        );
        case.name = name.to_string();
        cases.push(case);
    }

    let file = FriCommitFile {
        format_version: ORACLE_FORMAT_VERSION,
        plonky3_commit: PLONKY3_COMMIT,
        convention: "DNAC-internal FRI commit: layer-by-layer fold + Merkle root + transcript-derived beta; SHA3-512 throughout",
        cases,
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(out_path)?;
    f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
    f.write_all(b"\n")?;
    eprintln!("wrote {}", out_path.display());
    Ok(())
}

// ============================================================================
// Two-adic generators dump (Sub-sprint 2.1)
//
// Goldilocks has p - 1 = 2^32 · (2^32 - 1), so TWO_ADICITY = 32.
// Plonky3 hardcodes TWO_ADIC_GENERATORS[0..=32] such that:
//   TWO_ADIC_GENERATORS[0] = 1
//   TWO_ADIC_GENERATORS[i+1]^2 = TWO_ADIC_GENERATORS[i]
// i.e., index `k` gives a primitive 2^k-th root of unity.
// ============================================================================

use p3_field::TwoAdicField;

#[derive(Serialize)]
struct TwoAdicGenEntry {
    bits: u32,
    generator: String, // decimal u64
}

#[derive(Serialize)]
struct TwoAdicGensFile {
    format_version: &'static str,
    plonky3_commit: &'static str,
    two_adicity: u32,
    generators: Vec<TwoAdicGenEntry>,
}

fn dump_two_adic_gens(out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut gens = Vec::with_capacity(33);
    for bits in 0..=32u32 {
        let g = Goldilocks::two_adic_generator(bits as usize);
        gens.push(TwoAdicGenEntry {
            bits,
            generator: g.as_canonical_u64().to_string(),
        });
    }
    let file = TwoAdicGensFile {
        format_version: ORACLE_FORMAT_VERSION,
        plonky3_commit: PLONKY3_COMMIT,
        two_adicity: 32,
        generators: gens,
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(out_path)?;
    f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
    f.write_all(b"\n")?;
    eprintln!("wrote {}", out_path.display());
    Ok(())
}

// ============================================================================
// FRI fold dump (Sub-sprint 2.1) — arity-2 fold of Goldilocks² values
//
// DNAC-internal convention (natural pairing, NOT bit-reversed Plonky3 layout):
//   Input:  values[0..2H] in Goldilocks²
//           Row i of "matrix": (lo, hi) = (values[2i], values[2i+1])
//   beta:   Goldilocks² challenge
//   For each i ∈ [0, H):
//     x_i = g^i where g = two_adic_generator(log2(2H)) of size-2H subgroup
//     g_inv^i = g^{-i}
//     out[i] = (lo + hi) / 2 + (lo - hi) * beta * g_inv^i / 2
//
// To make C-side cross-validation independent of g computation, we ALSO emit
// the g_inv_powers[0..H] sequence as part of the test vector. C just consumes.
// ============================================================================

/// Compute fold result with DNAC-internal natural pairing.
fn fri_fold_arity2_oracle(values: &[GoldFp2], beta: GoldFp2, h: usize) -> Vec<GoldFp2> {
    assert_eq!(values.len(), 2 * h);
    // g = generator of order 2H subgroup
    let log_2h = (2 * h).trailing_zeros() as usize;
    let g = Goldilocks::two_adic_generator(log_2h);
    let g_inv = g.inverse();
    let half = Goldilocks::from_u64(2).inverse(); // 1/2 in base field
    // Precompute g_inv^i / 2 for i in 0..H
    let mut acc = half;
    let mut halve_inv_powers: Vec<Goldilocks> = Vec::with_capacity(h);
    for _ in 0..h {
        halve_inv_powers.push(acc);
        acc *= g_inv;
    }
    // Compute fold
    let mut out = Vec::with_capacity(h);
    for i in 0..h {
        let lo = values[2 * i];
        let hi = values[2 * i + 1];
        // (lo + hi) / 2 + (lo - hi) * beta * (g_inv^i / 2)
        // Note: halve_inv_powers[i] is base; we want it as ext for arithmetic.
        let hip_ext: GoldFp2 = halve_inv_powers[i].into();
        let half_ext: GoldFp2 = half.into();
        let term1 = (lo + hi) * half_ext;
        let term2 = (lo - hi) * beta * hip_ext;
        out.push(term1 + term2);
    }
    out
}

#[derive(Serialize)]
struct FriFoldCase {
    log_h: u32,
    h: u32,
    input_values: Vec<[String; 2]>,  // 2H Goldilocks² values
    beta: [String; 2],
    g_inv_powers: Vec<String>,        // H base-field values (g_inv^0, ..., g_inv^{H-1})
    halve_inv_powers: Vec<String>,    // H base-field values (g_inv^i / 2)
    expected_output: Vec<[String; 2]>, // H Goldilocks² values
}

#[derive(Serialize)]
struct FriFoldFile {
    format_version: &'static str,
    plonky3_commit: &'static str,
    convention: &'static str,
    cases: Vec<FriFoldCase>,
}

fn dump_fri_fold(out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = Vec::new();

    for &log_h in &[1u32, 2, 3, 4, 6, 8, 10] {
        let h = 1u32 << log_h;
        let n_inputs = 2 * h as usize;

        // Deterministic input values.
        let mut values: Vec<GoldFp2> = Vec::with_capacity(n_inputs);
        for i in 0..n_inputs {
            let a0 = canonical(deterministic_u64(900 + log_h, i as u32 * 2));
            let a1 = canonical(deterministic_u64(900 + log_h, i as u32 * 2 + 1));
            values.push(mk_fp2(a0, a1));
        }
        // Deterministic beta.
        let b0 = canonical(deterministic_u64(950 + log_h, 0));
        let b1 = canonical(deterministic_u64(950 + log_h, 1));
        let beta = mk_fp2(b0, b1);

        // Reference computation
        let expected = fri_fold_arity2_oracle(&values, beta, h as usize);

        // Compute g_inv_powers + halve_inv_powers for the C side
        let log_2h = (2 * h as usize).trailing_zeros() as usize;
        let g = Goldilocks::two_adic_generator(log_2h);
        let g_inv = g.inverse();
        let half = Goldilocks::from_u64(2).inverse();
        let mut acc_g = Goldilocks::ONE;
        let mut acc_half = half;
        let mut g_inv_powers: Vec<String> = Vec::with_capacity(h as usize);
        let mut halve_inv_powers: Vec<String> = Vec::with_capacity(h as usize);
        for _ in 0..h {
            g_inv_powers.push(acc_g.as_canonical_u64().to_string());
            halve_inv_powers.push(acc_half.as_canonical_u64().to_string());
            acc_g *= g_inv;
            acc_half *= g_inv;
        }

        cases.push(FriFoldCase {
            log_h,
            h,
            input_values: values.iter().map(|v| fp2_to_pair(*v)).collect(),
            beta: fp2_to_pair(beta),
            g_inv_powers,
            halve_inv_powers,
            expected_output: expected.iter().map(|v| fp2_to_pair(*v)).collect(),
        });
    }

    let file = FriFoldFile {
        format_version: ORACLE_FORMAT_VERSION,
        plonky3_commit: PLONKY3_COMMIT,
        convention: "DNAC-internal natural pairing: row_i = (values[2i], values[2i+1]); out[i] = (lo+hi)/2 + (lo-hi)*beta*g_inv^i/2",
        cases,
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(out_path)?;
    f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
    f.write_all(b"\n")?;
    eprintln!("wrote {}", out_path.display());
    Ok(())
}

// ============================================================================
// Transcript dump (Sprint 1.5) — Fiat-Shamir SHA3-512 chain
//
// Reference implementation: this Rust code defines the canonical behavior
// that C must byte-match. Spec in design doc § 4.3 (with F4 fix applied).
//
//   Init:   T₀ = SHA3-512( "DNAC_RP_TRANSCRIPT_V1\0\0\0" (24B) ||
//                          chain_id[32] || height_BE_u64 || tx_idx_BE_u32 ||
//                          public_input )
//   Absorb: T_{i+1} = SHA3-512( T_i || msg_i )
//   Challenge fp2:
//           seed = SHA3-512( T || "CHAL" || ctr_BE_u32 )
//           Rejection sample 2 Goldilocks elements from 8-byte BE chunks.
//           Counter increments after each call (whether or not we re-hash
//           due to rejection — see resample loop below).
//   Challenge query index (max_index):
//           seed = SHA3-512( T || "QRY"  || ctr_BE_u32 )
//           Rejection sample 1 u32 in [0, max_index) using threshold method.
// ============================================================================

const TRANSCRIPT_DOMAIN: &[u8] = b"DNAC_RP_TRANSCRIPT_V1\0\0\0"; // 24 bytes
const TRANSCRIPT_CHAL_TAG: &[u8] = b"CHAL";
const TRANSCRIPT_QRY_TAG: &[u8] = b"QRY\0"; // padded to 4 bytes to match CHAL

#[derive(Clone)]
struct OracleTranscript {
    state: [u8; 64],
    counter: u32,
}

impl OracleTranscript {
    fn init(chain_id: &[u8; 32], block_height: u64, tx_index: u32, public_input: &[u8]) -> Self {
        let mut h = Sha3_512::new();
        h.update(TRANSCRIPT_DOMAIN);
        h.update(chain_id);
        h.update(block_height.to_be_bytes());
        h.update(tx_index.to_be_bytes());
        h.update(public_input);
        let out = h.finalize();
        let mut state = [0u8; 64];
        state.copy_from_slice(&out);
        OracleTranscript { state, counter: 0 }
    }

    fn absorb(&mut self, msg: &[u8]) {
        let mut h = Sha3_512::new();
        h.update(self.state);
        h.update(msg);
        let out = h.finalize();
        self.state.copy_from_slice(&out);
    }

    fn squeeze(&self, tag: &[u8]) -> [u8; 64] {
        let mut h = Sha3_512::new();
        h.update(self.state);
        h.update(tag);
        h.update(self.counter.to_be_bytes());
        let out = h.finalize();
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&out);
        arr
    }

    /// Sample a Goldilocks² element by rejection sampling from squeezed bytes.
    /// Returns (a0, a1) canonical u64s. On rare exhaustion, increments counter
    /// and re-squeezes.
    fn challenge_fp2(&mut self) -> (u64, u64) {
        const P: u64 = GOLDILOCKS_P;
        loop {
            let seed = self.squeeze(TRANSCRIPT_CHAL_TAG);
            self.counter = self.counter.wrapping_add(1);
            let mut got_a0: Option<u64> = None;
            let mut got_a1: Option<u64> = None;
            // 8-byte chunks, BE.
            for chunk_idx in 0..8 {
                let off = chunk_idx * 8;
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&seed[off..off + 8]);
                let v = u64::from_be_bytes(buf);
                if v < P {
                    if got_a0.is_none() {
                        got_a0 = Some(v);
                    } else if got_a1.is_none() {
                        got_a1 = Some(v);
                        break;
                    }
                }
            }
            if let (Some(a0), Some(a1)) = (got_a0, got_a1) {
                return (a0, a1);
            }
            // All 8 chunks failed for at least one component — re-squeeze with
            // incremented counter (already incremented above).
        }
    }

    /// Sample u32 in [0, max_index) without modulo bias.
    fn challenge_query_index(&mut self, max_index: u32) -> u32 {
        assert!(max_index >= 1, "max_index must be >= 1");
        let threshold: u32 = if max_index == 0 { 0 } else { (u32::MAX / max_index) * max_index };
        loop {
            let seed = self.squeeze(TRANSCRIPT_QRY_TAG);
            self.counter = self.counter.wrapping_add(1);
            // 16 chunks of 4 bytes.
            for chunk_idx in 0..16 {
                let off = chunk_idx * 4;
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&seed[off..off + 4]);
                let v = u32::from_be_bytes(buf);
                if v < threshold {
                    return v % max_index;
                }
            }
            // All 16 chunks failed (extremely unlikely except for very small max_index).
        }
    }
}

#[derive(Serialize)]
struct TranscriptInit {
    chain_id_hex: String,
    block_height: u64,
    tx_index: u32,
    public_input_hex: String,
    initial_state_hex: String,
}

#[derive(Serialize)]
#[serde(tag = "action")]
enum TranscriptStep {
    #[serde(rename = "absorb")]
    Absorb {
        msg_hex: String,
        state_after_hex: String,
    },
    #[serde(rename = "challenge_fp2")]
    ChallengeFp2 {
        counter_before: u32,
        expected_a0: String,
        expected_a1: String,
        counter_after: u32,
        state_after_hex: String,
    },
    #[serde(rename = "challenge_query_index")]
    ChallengeQuery {
        counter_before: u32,
        max_index: u32,
        expected: u32,
        counter_after: u32,
        state_after_hex: String,
    },
}

#[derive(Serialize)]
struct TranscriptScenario {
    name: String,
    init: TranscriptInit,
    steps: Vec<TranscriptStep>,
}

#[derive(Serialize)]
struct TranscriptVectorFile {
    format_version: &'static str,
    plonky3_commit: &'static str,
    domain_separator_hex: String,
    chal_tag_hex: String,
    qry_tag_hex: String,
    scenarios: Vec<TranscriptScenario>,
}

/// Build a single scenario with a fixed script.
fn build_scenario(name: &str, chain_id: &[u8; 32], block_height: u64, tx_index: u32,
                  public_input: &[u8], script: Vec<(&str, &[u8], u32)>) -> TranscriptScenario {
    let mut t = OracleTranscript::init(chain_id, block_height, tx_index, public_input);
    let init = TranscriptInit {
        chain_id_hex: to_hex(chain_id),
        block_height,
        tx_index,
        public_input_hex: to_hex(public_input),
        initial_state_hex: to_hex(&t.state),
    };
    let mut steps = Vec::new();
    for (action, blob, num) in script {
        match action {
            "absorb" => {
                t.absorb(blob);
                steps.push(TranscriptStep::Absorb {
                    msg_hex: to_hex(blob),
                    state_after_hex: to_hex(&t.state),
                });
            }
            "challenge_fp2" => {
                let before = t.counter;
                let (a0, a1) = t.challenge_fp2();
                let after = t.counter;
                steps.push(TranscriptStep::ChallengeFp2 {
                    counter_before: before,
                    expected_a0: a0.to_string(),
                    expected_a1: a1.to_string(),
                    counter_after: after,
                    state_after_hex: to_hex(&t.state),
                });
            }
            "challenge_query_index" => {
                let before = t.counter;
                let idx = t.challenge_query_index(num);
                let after = t.counter;
                steps.push(TranscriptStep::ChallengeQuery {
                    counter_before: before,
                    max_index: num,
                    expected: idx,
                    counter_after: after,
                    state_after_hex: to_hex(&t.state),
                });
            }
            other => panic!("unknown action {other}"),
        }
    }
    TranscriptScenario {
        name: name.to_string(),
        init,
        steps,
    }
}

fn dump_transcript(out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut scenarios = Vec::new();

    // Scenario 1: minimal — all zeros chain_id + empty public_input.
    {
        let chain_id = [0u8; 32];
        let script: Vec<(&str, &[u8], u32)> = vec![
            ("challenge_fp2", &[][..], 0),
            ("absorb", b"hello"[..].as_ref(), 0),
            ("challenge_fp2", &[][..], 0),
            ("challenge_query_index", &[][..], 256),
        ];
        scenarios.push(build_scenario("minimal_zero", &chain_id, 0, 0, &[], script));
    }

    // Scenario 2: realistic — chain_id derived, public_input ~64B, 3 absorbs + many challenges.
    {
        let mut chain_id = [0u8; 32];
        for (i, b) in chain_id.iter_mut().enumerate() {
            *b = (deterministic_u64(500, i as u32) & 0xff) as u8;
        }
        let mut pubin = [0u8; 64];
        for (i, b) in pubin.iter_mut().enumerate() {
            *b = (deterministic_u64(501, i as u32) & 0xff) as u8;
        }
        let trace_root = [0xAAu8; 64];
        let quotient_root = [0xBBu8; 64];
        let fri_layer = [0xCCu8; 64];
        let script: Vec<(&str, &[u8], u32)> = vec![
            ("absorb", &trace_root[..], 0),
            ("challenge_fp2", &[][..], 0),
            ("absorb", &quotient_root[..], 0),
            ("challenge_fp2", &[][..], 0),
            ("challenge_fp2", &[][..], 0),
            ("absorb", &fri_layer[..], 0),
            ("challenge_query_index", &[][..], 1024),
            ("challenge_query_index", &[][..], 1024),
            ("challenge_query_index", &[][..], 16),
            ("challenge_fp2", &[][..], 0),
        ];
        scenarios.push(build_scenario("stark_like", &chain_id, 12345, 7, &pubin, script));
    }

    // Scenario 3: many small challenges to stress counter.
    {
        let chain_id = [0xFFu8; 32];
        let pubin = b"DNAC_RP_v3_test";
        let mut script: Vec<(&str, &[u8], u32)> = Vec::new();
        for _ in 0..20 {
            script.push(("challenge_fp2", &[][..], 0));
        }
        for _ in 0..20 {
            script.push(("challenge_query_index", &[][..], 100));
        }
        scenarios.push(build_scenario("many_challenges", &chain_id, 0xFFFF_FFFF, 0xFFFF, pubin, script));
    }

    // Scenario 4: interleave heavy absorbs and challenges; covers F4 fix path with tx_index != 0.
    {
        let chain_id = [0x42u8; 32];
        let pubin = b"";
        let big_msg = [0x77u8; 1024];
        let script: Vec<(&str, &[u8], u32)> = vec![
            ("absorb", &big_msg[..], 0),
            ("challenge_fp2", &[][..], 0),
            ("absorb", &big_msg[..], 0),
            ("challenge_query_index", &[][..], 7),
            ("absorb", &big_msg[..], 0),
            ("challenge_query_index", &[][..], 1),  // always 0
            ("challenge_query_index", &[][..], 2),
            ("challenge_fp2", &[][..], 0),
        ];
        scenarios.push(build_scenario("big_absorbs", &chain_id, 1_000_000, 99, pubin, script));
    }

    // Scenario 5: covers query_index with max_index very close to u32::MAX (low rejection).
    {
        let chain_id = [0x11u8; 32];
        let script: Vec<(&str, &[u8], u32)> = vec![
            ("challenge_query_index", &[][..], 0x8000_0000), // half range
            ("challenge_query_index", &[][..], 0xFFFF_FFFE),
            ("challenge_query_index", &[][..], 2),
            ("challenge_fp2", &[][..], 0),
        ];
        scenarios.push(build_scenario("large_max_index", &chain_id, 42, 42, &[], script));
    }

    let file = TranscriptVectorFile {
        format_version: ORACLE_FORMAT_VERSION,
        plonky3_commit: PLONKY3_COMMIT,
        domain_separator_hex: to_hex(TRANSCRIPT_DOMAIN),
        chal_tag_hex: to_hex(TRANSCRIPT_CHAL_TAG),
        qry_tag_hex: to_hex(TRANSCRIPT_QRY_TAG),
        scenarios,
    };

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(out_path)?;
    f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
    f.write_all(b"\n")?;
    eprintln!("wrote {}", out_path.display());
    Ok(())
}

// ============================================================================
// Merkle dump (Sprint 1.4) — SHA3-512 binary tree with DNAC domain separators
//
// Domain separators (design doc § 4.4, Option B unified):
//   "DNAC_RP_LEAF\0"  (13B)  — leaf hashing
//   "DNAC_RP_NODE\0"  (13B)  — internal node combination
//   "DNAC_RP_NULL\0"  (13B)  — null slot for under-full trees
//
// All hashes are SHA3-512 (FIPS-202), 64-byte output.
// ============================================================================

use sha3::{Digest, Sha3_512};

const MERKLE_LEAF_DOMAIN: &[u8] = b"DNAC_RP_LEAF\0";
const MERKLE_NODE_DOMAIN: &[u8] = b"DNAC_RP_NODE\0";
const MERKLE_NULL_DOMAIN: &[u8] = b"DNAC_RP_NULL\0";

/// Compute leaf hash: SHA3-512( "DNAC_RP_LEAF\0" || index_BE_u32 || value )
fn merkle_hash_leaf(index: u32, value: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(MERKLE_LEAF_DOMAIN);
    h.update(index.to_be_bytes());
    h.update(value);
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// Compute null hash: SHA3-512( "DNAC_RP_NULL\0" || index_BE_u32 )
fn merkle_hash_null(index: u32) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(MERKLE_NULL_DOMAIN);
    h.update(index.to_be_bytes());
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// Compute internal node: SHA3-512( "DNAC_RP_NODE\0" || left || right )
fn merkle_hash_node(left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(MERKLE_NODE_DOMAIN);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// Compute root over a leaf-hash array of length 2^depth (already hashed).
/// If leaves.len() < 2^depth, remaining slots fill with null hashes.
fn merkle_compute_root(leaves: &[[u8; 64]], depth: u32) -> [u8; 64] {
    let leaf_count = 1usize << depth;
    let mut level: Vec<[u8; 64]> = (0..leaf_count)
        .map(|i| {
            if i < leaves.len() {
                leaves[i]
            } else {
                merkle_hash_null(i as u32)
            }
        })
        .collect();
    for _ in 0..depth {
        let next: Vec<[u8; 64]> = level
            .chunks(2)
            .map(|pair| merkle_hash_node(&pair[0], &pair[1]))
            .collect();
        level = next;
    }
    level[0]
}

/// Build inclusion proof: sibling hash at each level from leaf up to root.
fn merkle_build_proof(leaves: &[[u8; 64]], depth: u32, target_index: u32) -> Vec<[u8; 64]> {
    let leaf_count = 1usize << depth;
    let mut level: Vec<[u8; 64]> = (0..leaf_count)
        .map(|i| {
            if i < leaves.len() {
                leaves[i]
            } else {
                merkle_hash_null(i as u32)
            }
        })
        .collect();
    let mut proof = Vec::with_capacity(depth as usize);
    let mut idx = target_index as usize;
    for _ in 0..depth {
        let sibling_idx = idx ^ 1;
        proof.push(level[sibling_idx]);
        let next: Vec<[u8; 64]> = level
            .chunks(2)
            .map(|pair| merkle_hash_node(&pair[0], &pair[1]))
            .collect();
        level = next;
        idx >>= 1;
    }
    proof
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[derive(Serialize)]
struct LeafHashCase {
    index: u32,
    value_hex: String, // input value bytes, hex
    hash_hex: String,  // SHA3-512 output, hex
}

#[derive(Serialize)]
struct NullHashCase {
    index: u32,
    hash_hex: String,
}

#[derive(Serialize)]
struct NodeHashCase {
    left_hex: String,
    right_hex: String,
    hash_hex: String,
}

#[derive(Serialize)]
struct RootCase {
    depth: u32,
    leaf_count: u32,
    /// Pre-hashed leaves (each 64-byte hex). Generator deterministically hashes
    /// (index, deterministic_value) tuples then includes both inputs and outputs.
    leaves_hex: Vec<String>,
    root_hex: String,
}

#[derive(Serialize)]
struct ProofCase {
    depth: u32,
    leaf_count: u32,
    target_index: u32,
    leaves_hex: Vec<String>,
    target_leaf_hex: String,
    proof_hex: Vec<String>,
    expected_root_hex: String,
}

#[derive(Serialize, Default)]
struct MerkleOperations {
    leaf_hash: Vec<LeafHashCase>,
    null_hash: Vec<NullHashCase>,
    node_hash: Vec<NodeHashCase>,
    root: Vec<RootCase>,
    proof: Vec<ProofCase>,
}

#[derive(Serialize)]
struct MerkleVectorFile {
    format_version: &'static str,
    plonky3_commit: &'static str,
    sha3_variant: &'static str,
    domain_separators: DomainSeparatorsDoc,
    operations: MerkleOperations,
}

#[derive(Serialize)]
struct DomainSeparatorsDoc {
    leaf_hex: String,
    node_hex: String,
    null_hex: String,
}

fn dump_merkle(out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Leaf hashing — vary input length and value content.
    let mut leaf_cases = Vec::new();
    // Edge cases: empty value, 1-byte, 64-byte (one full SHA3 absorb block).
    for (i, val) in [
        vec![],
        vec![0u8],
        vec![0xFFu8; 64],
        vec![0x42u8; 137], // crosses one block boundary
    ]
    .iter()
    .enumerate()
    {
        leaf_cases.push(LeafHashCase {
            index: i as u32,
            value_hex: to_hex(val),
            hash_hex: to_hex(&merkle_hash_leaf(i as u32, val)),
        });
    }
    // Deterministic body.
    for i in 0..256u32 {
        // Value: 32 bytes derived from index.
        let mut val = [0u8; 32];
        for (j, slot) in val.iter_mut().enumerate() {
            *slot = (deterministic_u64(100, i.wrapping_add(j as u32)) & 0xff) as u8;
        }
        leaf_cases.push(LeafHashCase {
            index: i,
            value_hex: to_hex(&val),
            hash_hex: to_hex(&merkle_hash_leaf(i, &val)),
        });
    }

    // Null hashing — single u32 index input. Cover small + large indices.
    let mut null_cases = Vec::new();
    for &i in &[0u32, 1, 2, 7, 1024, 0x1000_0000, 0xFFFF_FFFF] {
        null_cases.push(NullHashCase {
            index: i,
            hash_hex: to_hex(&merkle_hash_null(i)),
        });
    }
    for i in 0..256u32 {
        null_cases.push(NullHashCase {
            index: i,
            hash_hex: to_hex(&merkle_hash_null(i)),
        });
    }

    // Node hashing — pairs of 64-byte hashes.
    let mut node_cases = Vec::new();
    let zero64 = [0u8; 64];
    let ones64 = [0xFFu8; 64];
    node_cases.push(NodeHashCase {
        left_hex: to_hex(&zero64),
        right_hex: to_hex(&zero64),
        hash_hex: to_hex(&merkle_hash_node(&zero64, &zero64)),
    });
    node_cases.push(NodeHashCase {
        left_hex: to_hex(&ones64),
        right_hex: to_hex(&ones64),
        hash_hex: to_hex(&merkle_hash_node(&ones64, &ones64)),
    });
    node_cases.push(NodeHashCase {
        left_hex: to_hex(&zero64),
        right_hex: to_hex(&ones64),
        hash_hex: to_hex(&merkle_hash_node(&zero64, &ones64)),
    });
    for i in 0..256u32 {
        let l = merkle_hash_leaf(i, &i.to_be_bytes());
        let r = merkle_hash_leaf(i + 1, &(i + 1).to_be_bytes());
        node_cases.push(NodeHashCase {
            left_hex: to_hex(&l),
            right_hex: to_hex(&r),
            hash_hex: to_hex(&merkle_hash_node(&l, &r)),
        });
    }

    // Tree roots — various (depth, leaf_count) combinations.
    let mut root_cases = Vec::new();
    for &(depth, full_leaves) in &[
        (1u32, 1u32),   // 1 leaf, 1 null
        (1, 2),         // full
        (2, 1),
        (2, 4),
        (3, 5),         // partial fill
        (3, 8),         // full
        (4, 12),
        (5, 17),
        (6, 1),         // tons of null slots
        (8, 256),       // full medium tree
    ] {
        let leaf_count_pow2 = 1u32 << depth;
        assert!(full_leaves <= leaf_count_pow2);
        let leaves: Vec<[u8; 64]> = (0..full_leaves as usize)
            .map(|i| {
                let mut v = [0u8; 16];
                for (j, slot) in v.iter_mut().enumerate() {
                    *slot = (deterministic_u64(200 + depth, i as u32 * 16 + j as u32) & 0xff) as u8;
                }
                merkle_hash_leaf(i as u32, &v)
            })
            .collect();
        let root = merkle_compute_root(&leaves, depth);
        root_cases.push(RootCase {
            depth,
            leaf_count: full_leaves,
            leaves_hex: leaves.iter().map(|h| to_hex(h)).collect(),
            root_hex: to_hex(&root),
        });
    }

    // Inclusion proofs — for each root case, cover several leaf positions.
    let mut proof_cases = Vec::new();
    for &(depth, leaf_count) in &[
        (1u32, 2u32),
        (2, 3),
        (3, 5),
        (4, 10),
        (6, 33),
        (8, 200),
    ] {
        let leaves: Vec<[u8; 64]> = (0..leaf_count as usize)
            .map(|i| {
                let mut v = [0u8; 16];
                for (j, slot) in v.iter_mut().enumerate() {
                    *slot = (deterministic_u64(300 + depth, i as u32 * 16 + j as u32) & 0xff) as u8;
                }
                merkle_hash_leaf(i as u32, &v)
            })
            .collect();
        let expected_root = merkle_compute_root(&leaves, depth);
        let targets: Vec<u32> = if leaf_count <= 4 {
            (0..leaf_count).collect()
        } else {
            vec![0, leaf_count / 2, leaf_count - 1]
        };
        for target in targets {
            let proof = merkle_build_proof(&leaves, depth, target);
            proof_cases.push(ProofCase {
                depth,
                leaf_count,
                target_index: target,
                leaves_hex: leaves.iter().map(|h| to_hex(h)).collect(),
                target_leaf_hex: to_hex(&leaves[target as usize]),
                proof_hex: proof.iter().map(|h| to_hex(h)).collect(),
                expected_root_hex: to_hex(&expected_root),
            });
        }
    }

    let file = MerkleVectorFile {
        format_version: ORACLE_FORMAT_VERSION,
        plonky3_commit: PLONKY3_COMMIT,
        sha3_variant: "SHA3-512 (FIPS-202)",
        domain_separators: DomainSeparatorsDoc {
            leaf_hex: to_hex(MERKLE_LEAF_DOMAIN),
            node_hex: to_hex(MERKLE_NODE_DOMAIN),
            null_hex: to_hex(MERKLE_NULL_DOMAIN),
        },
        operations: MerkleOperations {
            leaf_hash: leaf_cases,
            null_hash: null_cases,
            node_hash: node_cases,
            root: root_cases,
            proof: proof_cases,
        },
    };

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(out_path)?;
    f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
    f.write_all(b"\n")?;
    eprintln!("wrote {}", out_path.display());
    Ok(())
}

// ============================================================================
// Field-ext dump (Sprint 1.3) — Goldilocks² operations
// ============================================================================

/// JSON schema for ext-field cases. Each value is a pair [a0, a1]
/// representing a0 + a1·X.
#[derive(Serialize)]
struct ExtBinaryCase {
    a: [String; 2],
    b: [String; 2],
    out: [String; 2],
}

#[derive(Serialize)]
struct ExtUnaryCase {
    a: [String; 2],
    out: [String; 2],
}

#[derive(Serialize, Default)]
struct ExtOperations {
    add: Vec<ExtBinaryCase>,
    sub: Vec<ExtBinaryCase>,
    mul: Vec<ExtBinaryCase>,
    neg: Vec<ExtUnaryCase>,
    sqr: Vec<ExtUnaryCase>,
    inv: Vec<ExtUnaryCase>,
}

#[derive(Serialize)]
struct ExtVectorFile {
    format_version: &'static str,
    plonky3_commit: &'static str,
    field_p: String,
    ext_irreducible_w: u64,
    operations: ExtOperations,
}

/// Construct a Goldilocks² element from a pair of u64 (a0 + a1·X).
fn mk_fp2(a0: u64, a1: u64) -> GoldFp2 {
    GoldFp2::new([Goldilocks::from_u64(a0), Goldilocks::from_u64(a1)])
}

/// Extract a Goldilocks² element as [a0, a1] decimal strings.
fn fp2_to_pair(x: GoldFp2) -> [String; 2] {
    let coeffs: &[Goldilocks] =
        <GoldFp2 as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&x);
    assert_eq!(coeffs.len(), 2, "Goldilocks² must have exactly 2 basis coefficients");
    [coeffs[0].as_canonical_u64().to_string(),
     coeffs[1].as_canonical_u64().to_string()]
}

fn ext_binary_cases(
    op_id: u32,
    n: usize,
    op: impl Fn(GoldFp2, GoldFp2) -> GoldFp2,
) -> Vec<ExtBinaryCase> {
    let mut out = Vec::with_capacity(n + 8);

    // Edge cases — covers (0, 0), (1, 1), (1, X), and zero-coefficient mixes.
    let edges: &[((u64, u64), (u64, u64))] = &[
        ((0, 0), (0, 0)),
        ((1, 0), (1, 0)),
        ((0, 1), (0, 1)),
        ((1, 1), (1, 1)),
        ((GOLDILOCKS_P - 1, 0), (1, 0)),
        ((0, GOLDILOCKS_P - 1), (0, 1)),
        ((GOLDILOCKS_P - 1, GOLDILOCKS_P - 1), (1, 1)),
        ((2, 3), (5, 7)),
    ];
    for &((a0, a1), (b0, b1)) in edges {
        let a = mk_fp2(a0, a1);
        let b = mk_fp2(b0, b1);
        out.push(ExtBinaryCase {
            a: [a0.to_string(), a1.to_string()],
            b: [b0.to_string(), b1.to_string()],
            out: fp2_to_pair(op(a, b)),
        });
    }

    // Deterministic body.
    for i in 0..(n as u32) {
        let a0 = canonical(deterministic_u64(op_id, i * 4));
        let a1 = canonical(deterministic_u64(op_id, i * 4 + 1));
        let b0 = canonical(deterministic_u64(op_id, i * 4 + 2));
        let b1 = canonical(deterministic_u64(op_id, i * 4 + 3));
        let a = mk_fp2(a0, a1);
        let b = mk_fp2(b0, b1);
        out.push(ExtBinaryCase {
            a: [a0.to_string(), a1.to_string()],
            b: [b0.to_string(), b1.to_string()],
            out: fp2_to_pair(op(a, b)),
        });
    }
    out
}

fn ext_unary_cases(
    op_id: u32,
    n: usize,
    skip_zero: bool,
    op: impl Fn(GoldFp2) -> GoldFp2,
) -> Vec<ExtUnaryCase> {
    let mut out = Vec::with_capacity(n + 8);

    let edge_inputs: &[(u64, u64)] = if skip_zero {
        // inv(0) undefined; also skip 0 + 0·X since norm = 0 — same problem.
        &[(1, 0), (0, 1), (1, 1), (2, 3), (GOLDILOCKS_P - 1, 0)]
    } else {
        &[(0, 0), (1, 0), (0, 1), (1, 1), (GOLDILOCKS_P - 1, 0), (0, GOLDILOCKS_P - 1)]
    };
    for &(a0, a1) in edge_inputs {
        let a = mk_fp2(a0, a1);
        out.push(ExtUnaryCase {
            a: [a0.to_string(), a1.to_string()],
            out: fp2_to_pair(op(a)),
        });
    }

    for i in 0..(n as u32) {
        let mut a0 = canonical(deterministic_u64(op_id, i * 2));
        let mut a1 = canonical(deterministic_u64(op_id, i * 2 + 1));
        // For inv: norm = a0² - W·a1² != 0 mod p, which is rare to violate
        // with random inputs but ensure at least one component is non-zero.
        if skip_zero && a0 == 0 && a1 == 0 {
            a0 = 1;
            a1 = 0;
        }
        let a = mk_fp2(a0, a1);
        out.push(ExtUnaryCase {
            a: [a0.to_string(), a1.to_string()],
            out: fp2_to_pair(op(a)),
        });
    }
    out
}

fn dump_field_ext(out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let ops = ExtOperations {
        add: ext_binary_cases(10, CASES_PER_OP, |a, b| a + b),
        sub: ext_binary_cases(11, CASES_PER_OP, |a, b| a - b),
        mul: ext_binary_cases(12, CASES_PER_OP, |a, b| a * b),
        neg: ext_unary_cases(13, CASES_PER_OP, false, |a| -a),
        sqr: ext_unary_cases(14, CASES_PER_OP, false, |a| a.square()),
        inv: ext_unary_cases(15, CASES_PER_OP, true, |a| a.inverse()),
    };

    let file = ExtVectorFile {
        format_version: ORACLE_FORMAT_VERSION,
        plonky3_commit: PLONKY3_COMMIT,
        field_p: GOLDILOCKS_P.to_string(),
        ext_irreducible_w: 7, // x² - 7 per design doc § 6.3
        operations: ops,
    };

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(out_path)?;
    f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
    f.write_all(b"\n")?;
    eprintln!("wrote {}", out_path.display());
    Ok(())
}

// ============================================================================
// Field-ops dump (Sprint 1.1)
// ============================================================================

fn dump_field_ops(out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let ops = Operations {
        add: binary_cases(1, CASES_PER_OP, |a, b| a + b),
        sub: binary_cases(2, CASES_PER_OP, |a, b| a - b),
        mul: binary_cases(3, CASES_PER_OP, |a, b| a * b),
        neg: unary_cases(4, CASES_PER_OP, false, |a| -a),
        sqr: unary_cases(5, CASES_PER_OP, false, |a| a.square()),
        inv: unary_cases(6, CASES_PER_OP, true, |a| a.inverse()),
        pow: pow_cases(7, CASES_PER_OP),
    };

    let file = VectorFile {
        format_version: ORACLE_FORMAT_VERSION,
        plonky3_commit: PLONKY3_COMMIT,
        field_p: GOLDILOCKS_P.to_string(),
        operations: ops,
    };

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(out_path)?;
    f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
    f.write_all(b"\n")?;
    eprintln!("wrote {}", out_path.display());
    Ok(())
}
