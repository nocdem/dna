# Crypto Reorganization — Post-Completion Test Plan

**Date:** 2026-03-11
**Prerequisite:** All 4 phases of crypto-reorganization.md completed, all builds pass.
**Goal:** Verify every signing algorithm works correctly after file moves and refactoring.

---

## 1. Build Tests (MUST ALL PASS)

```bash
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)   # zero warnings
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)        # zero warnings
cd /opt/dna/dnac/build && cmake .. && make -j$(nproc)         # zero warnings
```

## 2. Unit Tests (MUST ALL PASS)

```bash
cd /opt/dna/messenger/build && ctest --output-on-failure
cd /opt/dna/nodus/build && ctest --output-on-failure
cd /opt/dna/dnac/build && ctest --output-on-failure
```

## 3. Flutter Build

```bash
cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux
```

## 4. Signing Integration Tests (Real TX)

Each test verifies a specific signing algorithm survived the reorganization.

### 4.1 secp256k1 — ETH Transfer (EIP-155 v calculation)
```bash
# Sends ERC-20 USDT — tests secp256k1_sign_hash() with recovery_id for EIP-155
dna-messenger-cli wallet send-tokens 0 ETH USDT <test_address> 1
```
**Verifies:** `secp256k1_sign_hash()` → `eth_tx_sign()` → EIP-155 v = recovery_id + chainId*2 + 35

### 4.2 secp256k1 — ETH DEX Swap (router TX)
```bash
dna-messenger-cli dex swap 0 ETH USDT 0.001
```
**Verifies:** `secp256k1_sign_hash()` → `eth_tx_sign()` → V2/V3 router calldata + Flashbots

### 4.3 secp256k1 — TRON Transfer (v = 27 + recovery_id)
```bash
dna-messenger-cli wallet send-tokens 0 TRON TRX <test_address> 1
```
**Verifies:** `secp256k1_sign_hash()` → `trx_tx_sign()` → v = 27 + recovery_id

### 4.4 Ed25519 — SOL Transfer
```bash
dna-messenger-cli wallet send-tokens 0 SOL SOL <test_address> 0.001
```
**Verifies:** `ed25519_sign()` → `sol_sign_message()` → Ed25519 signature

### 4.5 Ed25519 — SOL SPL Token (USDT)
```bash
dna-messenger-cli wallet send-tokens 0 SOL USDT <test_address> 0.1
```
**Verifies:** `ed25519_sign()` → SPL transfer instruction signing

### 4.6 Cellframe Dilithium MODE_1 — CF20 Transfer
```bash
dna-messenger-cli wallet send-tokens 0 CELL CPUNK <test_address> 1
```
**Verifies:** `cellframe_sign_transaction()` → Cellframe Dilithium MODE_1 (moved to sign/cellframe_dilithium/)

### 4.7 Dilithium5 — Messenger Message
```bash
dna-messenger-cli send punk "crypto reorg test"
```
**Verifies:** `qgp_dsa87_sign()` → DHT message signing (moved to sign/qgp_dilithium.c, reference impl to sign/dsa/)

## 5. Wallet Addresses (Sanity Check)

Run before AND after reorganization. Addresses must be identical.

```bash
dna-messenger-cli wallet list
```

Expected:
```
0. Ethereum  — 0x86dC0a643580705c7Ca257250e68C952B236c551
1. Solana    — F5APXDKWWQF1LasKWmhecjWcspaC1xVzcuZb3aBUFHND
2. Tron      — TSfqeFtKHVz6zxkHiN7aAWGpRPEiPQgVFw
3. Cellframe — Rj7J7MiX2bWy8sNyZGPj8fqNUDv3U1jofTVQJAVCwx9qZDihERqghBtnT31XjZ7qaSbXJ6pCFdFAaY5AFpWNjBGZFsCVGtKrUDSmxmsE
```

If addresses change → key derivation is broken → DO NOT PUSH.

## 6. DEX Quote (Non-destructive check)

```bash
dna-messenger-cli dex quote ETH USDT 0.001
```

Should return 4 quotes (Uniswap v2/v3, PancakeSwap v2/v3). If zero → keccak256 or RPC broken.

---

## Test Order

1. Builds (Section 1)
2. Unit tests (Section 2)
3. Flutter build (Section 3)
4. Wallet addresses sanity (Section 5) — compare with expected
5. DEX quote (Section 6) — non-destructive
6. Signing tests 4.1–4.7 — real TX, smallest amounts

## Pass Criteria

- ALL builds: zero warnings, zero errors
- ALL unit tests: pass
- ALL wallet addresses: unchanged
- ALL 7 signing tests: TX confirmed on-chain
- Flutter build: success
