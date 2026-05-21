#!/usr/bin/env bash
# shared/crypto/zk/run_tests.sh
#
# Full Faz 1 pipeline:
#   1. Build Plonky3 oracle (Rust, requires cargo).
#   2. Regenerate all test vectors.
#   3. Verify vector SHA-256 hashes match the pinned expectations.
#      Drift → fail (= upstream Plonky3 behavior changed → design-doc revision required).
#   4. Build C test binaries.
#   5. Run all 4 cross-validation suites.
#
# Exit codes:
#   0  — all green
#   1  — at least one test failed
#   2  — oracle build or hash drift
#   3  — environment problem (cargo / gcc missing)
#
# Usage:
#   ./run_tests.sh                    (verify only — skip oracle regen)
#   ./run_tests.sh --regen            (regen vectors, verify hashes, run tests)
#   FORCE_REGEN=1 ./run_tests.sh      (same as --regen)
#
# Used by:
#   - Sprint 1.6 manual verification (now)
#   - GitLab CI job `zk-test` (future, Faz 1 closure)

set -euo pipefail

cd "$(dirname "$0")"

REGEN=0
if [[ "${1:-}" == "--regen" ]] || [[ "${FORCE_REGEN:-0}" == "1" ]]; then
    REGEN=1
fi

# --- env checks ----------------------------------------------------------

if ! command -v gcc >/dev/null 2>&1; then
    echo "error: gcc not found" >&2
    exit 3
fi

# Sourcing ~/.cargo/env is the rustup convention.
if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

if [[ $REGEN -eq 1 ]] && ! command -v cargo >/dev/null 2>&1; then
    echo "error: --regen requested but cargo not in PATH (install rustup)" >&2
    exit 3
fi

# --- oracle regen --------------------------------------------------------

if [[ $REGEN -eq 1 ]]; then
    echo "[1/5] Building Plonky3 oracle (frozen Cargo.lock)..."
    (
        cd tools/plonky3_oracle
        cargo build --release --frozen
    )
    echo "[2/5] Regenerating test vectors..."
    (
        cd tools/plonky3_oracle
        cargo run --release --frozen -- dump-field-ops --out ../vectors/field_ops.json
        cargo run --release --frozen -- dump-field-ext --out ../vectors/field_ext.json
        cargo run --release --frozen -- dump-merkle    --out ../vectors/merkle.json
        cargo run --release --frozen -- dump-transcript --out ../vectors/transcript.json
    )
else
    echo "[1/5] Skipping oracle build (no --regen)"
    echo "[2/5] Using cached vectors in tools/vectors/"
fi

# --- hash verify ---------------------------------------------------------

echo "[3/5] Verifying vector hashes against .expected_hashes..."
(
    cd tools/vectors
    if ! sha256sum -c --status .expected_hashes; then
        echo "  HASH DRIFT — at least one vector differs from pinned hash" >&2
        echo "  This means either: (a) you regenerated against a different Plonky3" >&2
        echo "  commit, or (b) the oracle's deterministic input generation changed." >&2
        echo "  Required action: update Cargo.toml pin AND design doc § 0 'Plonky3" >&2
        echo "  reference version pinned' line, then commit new hashes." >&2
        sha256sum *.json | tee /dev/stderr > /tmp/observed_hashes
        echo
        echo "  Observed vs expected diff:"
        diff <(sort .expected_hashes) <(sort /tmp/observed_hashes) >&2 || true
        exit 2
    fi
    echo "  all 4 vector hashes match pinned expectations"
)

# --- build C tests -------------------------------------------------------

echo "[4/5] Building C test binaries..."
make -s all

# --- run C tests ---------------------------------------------------------

echo "[5/5] Running cross-validation suites..."
make -s test
