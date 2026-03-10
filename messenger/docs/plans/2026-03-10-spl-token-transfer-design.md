# SPL Token Transfer Design

**Date:** 2026-03-10
**Status:** Approved
**Author:** nocdem

## Problem

SPL token balances can be queried (`sol_spl_get_balance_by_symbol`) but transfers are not implemented. `sol_chain_send()` and `blockchain_send_tokens_with_seed()` return "SPL tokens not yet supported" for non-native Solana tokens.

## Scope

1. SPL token send — any mint address, with automatic ATA creation
2. SPL token transaction history — show transfers in tx history
3. USDC balance — add to all chains (SOL, ETH, TRX, CELL)

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Token support | Any mint address + symbol registry shortcuts | Future-proof for custom tokens |
| ATA creation | Sender auto-creates if missing | Standard behavior (Phantom, Solflare) |
| TX history | Include SPL transfers | Send + history together is coherent |
| Fee estimation | Check ATA existence, show full fee | User sees exact cost before sending |
| USDC balance | Add to all chains | Consistency across wallets |

## Architecture

```
Flutter UI (send dialog)
    |
    v FFI
dna_engine_wallet.c -> blockchain_send_tokens_with_seed()
    |                        |
    |                   BLOCKCHAIN_SOLANA case
    |                        |
    |               token != NULL && token != "SOL"
    |                        |
    |                   sol_spl_send()
    |                        |
    v                        v
sol_spl.c               sol_rpc.c
  - sol_spl_send()        - getTokenAccountsByOwner (ATA check)
  - sol_spl_build_tx()    - getMinimumBalanceForRentExemption
  - sol_spl_find_ata()    - sendTransaction
```

## New Functions (sol_spl.h/c)

| Function | Description |
|----------|-------------|
| `sol_spl_derive_ata()` | Derive ATA address (PDA) from owner + mint |
| `sol_spl_check_ata()` | RPC check if ATA exists |
| `sol_spl_build_transfer_tx()` | Build transfer TX (with ATA create if needed) |
| `sol_spl_send()` | High-level: ATA check -> build -> sign -> send |
| `sol_spl_estimate_fee()` | Check ATA, return exact fee |

## SPL Transfer TX Structure

**ATA exists** (1 instruction):
1. Token Program `Transfer` (index=3): from_ata -> to_ata

**ATA missing** (2 instructions):
1. Associated Token Program `CreateAssociatedTokenAccount`
2. Token Program `Transfer`

**Account keys (ATA exists):**
- sender (signer, writable)
- sender_ata (writable)
- recipient_ata (writable)
- sender (signer — token owner/delegate)
- Token Program

**Account keys (ATA missing — additional):**
- sender (signer, writable, fee payer)
- recipient_ata (writable)
- recipient
- mint
- System Program
- Token Program
- Associated Token Program

## Fee Estimation

```
ATA exists:   5000 lamports (0.000005 SOL)
ATA missing:  5000 + rent_exempt (~2039280 lamports) = ~0.00204 SOL
```

## Error Codes

| Code | Condition |
|------|-----------|
| 0 | Success |
| -1 | General error |
| -2 | Insufficient token balance |
| -3 | Insufficient SOL for rent/fees |
| -4 | Invalid mint address |

## Files Changed

| File | Change |
|------|--------|
| `sol_spl.h` | New transfer function declarations |
| `sol_spl.c` | Transfer implementation (ATA, TX build, sign, send) |
| `sol_chain.c` | `sol_chain_send()` + `sol_chain_get_balance()` SPL support |
| `blockchain_wallet.c` | Solana SPL send path + USDC balance |
| `dna_engine_wallet.c` | USDC balance slot for all chains |
| `sol_rpc.c` | SPL token transfer history parsing |
| `docs/functions/blockchain.md` | New function signatures |
