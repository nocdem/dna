#!/bin/bash
# DNA Messenger: Rename cryptographic primitives to NIST standard names
# dilithium3 → mldsa87 (ML-DSA-87, FIPS 204)
# kyber512 → mlkem1024 (ML-KEM-1024, FIPS 203)
#
# EXCLUDES: All Cellframe integration code

set -e  # Exit on error

echo "======================================"
echo "DNA Messenger Crypto Rename to NIST Names"
echo "======================================"
echo ""

# Backup current state
echo "[1/10] Creating backup..."
git stash push -m "Pre-NIST-rename backup $(date +%Y%m%d-%H%M%S)"

#==============================================================================
# PHASE 1: RENAME DIRECTORIES
#==============================================================================
echo ""
echo "[2/10] Phase 1: Renaming directories..."

# Rename crypto directories (preserve git history)
if [ -d "crypto/kyber512" ]; then
    git mv crypto/kyber512 crypto/mlkem1024
    echo "  ✓ crypto/kyber512 → crypto/mlkem1024"
fi

if [ -d "crypto/dilithium" ]; then
    git mv crypto/dilithium crypto/mldsa87
    echo "  ✓ crypto/dilithium → crypto/mldsa87"
fi

# Note: crypto/cellframe_dilithium is NOT renamed (excluded)

#==============================================================================
# PHASE 2: RENAME FILES INSIDE DIRECTORIES
#==============================================================================
echo ""
echo "[3/10] Phase 2: Renaming files inside crypto libraries..."

# Kyber/ML-KEM files
cd crypto/mlkem1024
if [ -f "kyber512.h" ]; then git mv kyber512.h mlkem1024.h; fi
if [ -f "kyber512.pri" ]; then git mv kyber512.pri mlkem1024.pri; fi
if [ -f "poly_kyber.h" ]; then git mv poly_kyber.h poly_mlkem.h; fi
if [ -f "poly_kyber.c" ]; then git mv poly_kyber.c poly_mlkem.c; fi
if [ -f "polyvec_kyber.h" ]; then git mv polyvec_kyber.h polyvec_mlkem.h; fi
if [ -f "polyvec_kyber.c" ]; then git mv polyvec_kyber.c polyvec_mlkem.c; fi
if [ -f "ntt_kyber.h" ]; then git mv ntt_kyber.h ntt_mlkem.h; fi
if [ -f "ntt_kyber.c" ]; then git mv ntt_kyber.c ntt_mlkem.c; fi
if [ -f "reduce_kyber.h" ]; then git mv reduce_kyber.h reduce_mlkem.h; fi
if [ -f "reduce_kyber.c" ]; then git mv reduce_kyber.c reduce_mlkem.c; fi
if [ -f "fips202_kyber.h" ]; then git mv fips202_kyber.h fips202_mlkem.h; fi
if [ -f "fips202_kyber.c" ]; then git mv fips202_kyber.c fips202_mlkem.c; fi
if [ -f "sha256_kyber.c" ]; then git mv sha256_kyber.c sha256_mlkem.c; fi
if [ -f "sha512_kyber.c" ]; then git mv sha512_kyber.c sha512_mlkem.c; fi
cd ../..
echo "  ✓ Renamed Kyber→ML-KEM files (13 files)"

# Dilithium/ML-DSA files (none have suffix in filename currently)
# Just the params.h comment needs updating
echo "  ✓ ML-DSA files (no renames needed, just content updates)"

#==============================================================================
# PHASE 3: RENAME ROOT-LEVEL FILES
#==============================================================================
echo ""
echo "[4/10] Phase 3: Renaming root-level crypto files..."

git mv qgp_dilithium.h qgp_mldsa87.h
git mv qgp_dilithium.c qgp_mldsa87.c
git mv qgp_kyber.h qgp_mlkem1024.h
git mv qgp_kyber.c qgp_mlkem1024.c
git mv kyber_deterministic.h mlkem1024_deterministic.h
git mv kyber_deterministic.c mlkem1024_deterministic.c

echo "  ✓ Renamed 6 root-level files"

#==============================================================================
# PHASE 4: TEXT REPLACEMENTS (BULK SED)
#==============================================================================
echo ""
echo "[5/10] Phase 4: Updating text content (constants, functions, variables)..."

# Build list of files to process (EXCLUDE cellframe)
FILES=$(find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "CMakeLists.txt" \) \
    ! -path "*/build/*" \
    ! -path "*/build-release/*" \
    ! -path "*/.git/*" \
    ! -path "*/crypto/cellframe_dilithium/*" \
    ! -name "cellframe_*.c" \
    ! -name "cellframe_*.h" \
    ! -name "wallet.c" \
    ! -name "wallet.h")

# Count total files
TOTAL=$(echo "$FILES" | wc -l)
echo "  Processing $TOTAL files (excluding Cellframe)..."

# Apply replacements
echo "$FILES" | while read file; do
    # Skip if file doesn't exist
    [ -f "$file" ] || continue

    # Dilithium → ML-DSA-87
    sed -i 's/QGP_DILITHIUM3_/QGP_MLDSA87_/g' "$file"
    sed -i 's/qgp_dilithium3_/qgp_mldsa87_/g' "$file"
    sed -i 's/QGP_KEY_TYPE_DILITHIUM3/QGP_KEY_TYPE_MLDSA87/g' "$file"
    sed -i 's/QGP_SIG_TYPE_DILITHIUM/QGP_SIG_TYPE_MLDSA87/g' "$file"
    sed -i 's/dilithium3\.pqkey/mldsa87.pqkey/g' "$file"
    sed -i 's/-dilithium3\.pqkey/-mldsa87.pqkey/g' "$file"
    sed -i 's/dilithium_pk/mldsa87_pk/g' "$file"
    sed -i 's/dilithium_sk/mldsa87_sk/g' "$file"
    sed -i 's/dilithium_pubkey/mldsa87_pubkey/g' "$file"
    sed -i 's/dilithium_privkey/mldsa87_privkey/g' "$file"
    sed -i 's/dilithium_signature/mldsa87_signature/g' "$file"

    # Kyber → ML-KEM-1024
    sed -i 's/QGP_KYBER512_/QGP_MLKEM1024_/g' "$file"
    sed -i 's/qgp_kyber512_/qgp_mlkem1024_/g' "$file"
    sed -i 's/QGP_KEY_TYPE_KYBER512/QGP_KEY_TYPE_MLKEM1024/g' "$file"
    sed -i 's/DAP_ENC_KEY_TYPE_KEM_KYBER512/DAP_ENC_KEY_TYPE_KEM_MLKEM1024/g' "$file"
    sed -i 's/kyber512\.pqkey/mlkem1024.pqkey/g' "$file"
    sed -i 's/-kyber512\.pqkey/-mlkem1024.pqkey/g' "$file"
    sed -i 's/kyber_pk/mlkem1024_pk/g' "$file"
    sed -i 's/kyber_sk/mlkem1024_sk/g' "$file"
    sed -i 's/kyber_pubkey/mlkem1024_pubkey/g' "$file"
    sed -i 's/kyber_privkey/mlkem1024_privkey/g' "$file"
    sed -i 's/kyber_ciphertext/mlkem1024_ciphertext/g' "$file"
    sed -i 's/kyber_ct/mlkem1024_ct/g' "$file"

    # Include paths
    sed -i 's|crypto/dilithium/|crypto/mldsa87/|g' "$file"
    sed -i 's|crypto/kyber512/|crypto/mlkem1024/|g' "$file"
    sed -i 's|#include "qgp_dilithium\.h"|#include "qgp_mldsa87.h"|g' "$file"
    sed -i 's|#include "qgp_kyber\.h"|#include "qgp_mlkem1024.h"|g' "$file"
    sed -i 's|#include "kyber_deterministic\.h"|#include "mlkem1024_deterministic.h"|g' "$file"

    # Internal crypto library includes
    sed -i 's|"kyber512\.h"|"mlkem1024.h"|g' "$file"
    sed -i 's|"poly_kyber\.h"|"poly_mlkem.h"|g' "$file"
    sed -i 's|"ntt_kyber\.h"|"ntt_mlkem.h"|g' "$file"
    sed -i 's|"reduce_kyber\.h"|"reduce_mlkem.h"|g' "$file"
    sed -i 's|"fips202_kyber\.h"|"fips202_mlkem.h"|g' "$file"

    # CMake library names
    sed -i 's/kyber512/mlkem1024/g' "$file"
    sed -i 's/dilithium/mldsa87/g' "$file"

    # Comments (algorithm names)
    sed -i 's/Kyber512/ML-KEM-1024/g' "$file"
    sed -i 's/Dilithium3/ML-DSA-87/g' "$file"
done

echo "  ✓ Applied text replacements to $TOTAL files"

#==============================================================================
# PHASE 5: FIX OVER-REPLACEMENTS (Cellframe protection)
#==============================================================================
echo ""
echo "[6/10] Phase 5: Reverting over-replacements in Cellframe code..."

# Fix crypto/cellframe_dilithium (if accidentally processed)
if [ -d "crypto/cellframe_dilithium" ]; then
    git checkout crypto/cellframe_dilithium/ 2>/dev/null || true
    echo "  ✓ Restored crypto/cellframe_dilithium/"
fi

# Fix cellframe files in root
for file in cellframe_*.c cellframe_*.h wallet.c wallet.h; do
    if [ -f "$file" ]; then
        git checkout "$file" 2>/dev/null || true
    fi
done
echo "  ✓ Restored Cellframe files"

#==============================================================================
# PHASE 6: UPDATE DOCUMENTATION
#==============================================================================
echo ""
echo "[7/10] Phase 6: Updating documentation..."

# README.md
if [ -f "README.md" ]; then
    sed -i 's/Kyber1024/ML-KEM-1024/g' README.md
    sed -i 's/Kyber512/ML-KEM-1024/g' README.md
    sed -i 's/Dilithium5/ML-DSA-87/g' README.md
    sed -i 's/Dilithium3/ML-DSA-87/g' README.md
    echo "  ✓ Updated README.md"
fi

# ROADMAP.md
if [ -f "ROADMAP.md" ]; then
    sed -i 's/Kyber1024/ML-KEM-1024/g' ROADMAP.md
    sed -i 's/Kyber512/ML-KEM-1024/g' ROADMAP.md
    sed -i 's/Dilithium5/ML-DSA-87/g' ROADMAP.md
    sed -i 's/Dilithium3/ML-DSA-87/g' ROADMAP.md
    echo "  ✓ Updated ROADMAP.md"
fi

# CLAUDE.md
if [ -f "CLAUDE.md" ]; then
    sed -i 's/Kyber512/ML-KEM-1024/g' CLAUDE.md
    sed -i 's/Dilithium3/ML-DSA-87/g' CLAUDE.md
    echo "  ✓ Updated CLAUDE.md"
fi

# Design docs
if [ -d "futuredesign" ]; then
    find futuredesign -name "*.md" -exec sed -i 's/Kyber512/ML-KEM-1024/g' {} \;
    find futuredesign -name "*.md" -exec sed -i 's/Dilithium3/ML-DSA-87/g' {} \;
    echo "  ✓ Updated futuredesign/*.md"
fi

#==============================================================================
# PHASE 7: FIX SPECIAL CASES
#==============================================================================
echo ""
echo "[8/10] Phase 7: Fixing special cases and edge cases..."

# Fix crypto library namespace defines (should keep original pqcrystals names)
sed -i 's/pqcrystals_mldsa87/pqcrystals_dilithium5/g' crypto/mldsa87/*.c crypto/mldsa87/*.h
sed -i 's/pqcrystals_mlkem1024/pqcrystals_kyber1024/g' crypto/mlkem1024/*.c crypto/mlkem1024/*.h

echo "  ✓ Fixed crypto library internal names"

#==============================================================================
# PHASE 8: VERIFY CHANGES
#==============================================================================
echo ""
echo "[9/10] Phase 8: Verifying changes..."

# Check for leftover references (excluding Cellframe)
LEFTOVER_DIL=$(grep -r "dilithium3\|QGP_DILITHIUM3" . \
    --include="*.c" --include="*.h" --include="*.cpp" \
    --exclude-dir=build --exclude-dir=build-release --exclude-dir=.git \
    --exclude-dir=cellframe_dilithium --exclude="cellframe_*" --exclude="wallet.*" \
    | grep -v "Binary file" | wc -l)

LEFTOVER_KYB=$(grep -r "kyber512\|QGP_KYBER512" . \
    --include="*.c" --include="*.h" --include="*.cpp" \
    --exclude-dir=build --exclude-dir=build-release --exclude-dir=.git \
    --exclude-dir=cellframe_dilithium --exclude="cellframe_*" --exclude="wallet.*" \
    | grep -v "Binary file" | wc -l)

echo "  Leftover 'dilithium3/QGP_DILITHIUM3': $LEFTOVER_DIL (should be 0)"
echo "  Leftover 'kyber512/QGP_KYBER512': $LEFTOVER_KYB (should be 0)"

if [ $LEFTOVER_DIL -gt 0 ] || [ $LEFTOVER_KYB -gt 0 ]; then
    echo ""
    echo "  ⚠️  WARNING: Some legacy names remain (review manually)"
fi

#==============================================================================
# DONE
#==============================================================================
echo ""
echo "[10/10] Refactoring complete!"
echo ""
echo "======================================"
echo "Summary:"
echo "  - Renamed 2 crypto directories"
echo "  - Renamed 19+ files"
echo "  - Updated $TOTAL source files"
echo "  - Excluded: crypto/cellframe_dilithium, wallet.c, cellframe_*"
echo ""
echo "Next steps:"
echo "  1. Review changes: git status"
echo "  2. Build: mkdir build && cd build && cmake .. && make"
echo "  3. Test: Run key generation, messaging"
echo "  4. Commit: git commit -m 'Refactor: Rename to NIST standard names'"
echo "======================================"
