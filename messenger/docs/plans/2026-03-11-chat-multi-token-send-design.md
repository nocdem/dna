# Chat Multi-Token Send Design

**Date:** 2026-03-11
**Status:** APPROVED

## Summary

Extend the existing "Send CPUNK" button in chat to support sending any token on any chain. Single flat dropdown list of token/chain combinations, filtered by contact's available wallet addresses.

## Token List

Filtered by contact's DHT profile wallet addresses:

| Contact has `backbone` | Contact has `eth` | Contact has `sol` | Contact has `trx` |
|---|---|---|---|
| CELL (Cellframe) | ETH (Ethereum) | SOL (Solana) | TRX (TRON) |
| CPUNK (Cellframe) | USDT (Ethereum) | USDT (Solana) | USDT (TRON) |
| USDC (Cellframe) | USDC (Ethereum) | USDC (Solana) | USDC (TRON) |

## UX Flow

1. User taps "$" button in chat AppBar
2. `_ChatSendSheet` opens with token selector dropdown (default: CELL)
3. Only tokens for chains where contact has a wallet address are shown
4. Selected token's balance is displayed dynamically
5. User enters amount, taps "Send"
6. `sendTokens()` called with correct token/network/chain
7. Transfer message JSON written to chat conversation

## "Backbone" → "Cellframe" Rename

All occurrences of "Backbone" network name replaced with "Cellframe":
- Flutter UI labels
- Flutter → C API calls (`network: 'Cellframe'`)
- C engine network string mapping
- Transfer message JSON (`'network': 'Cellframe'`)
- No backward compatibility for old messages

## Technical Changes

### Flutter (lib/)
1. **`_ChatSendSheet`** in `chat_screen.dart` — Add token dropdown, resolve wallet address per chain, show balance per token, send with correct params
2. **`wallet_provider.dart`** — Update `'backbone'` → `'cellframe'` in `_getProfileAddress()`
3. **Button tooltip** — "Send CPUNK" → "Send Tokens"

### C Engine
4. **`dna_engine_wallet.c`** — Accept `'Cellframe'` as network string (in addition to or replacing `'Backbone'`)

### Transfer Message JSON Format
```json
{
  "type": "token_transfer",
  "amount": "50",
  "token": "USDT",
  "network": "Ethereum",
  "chain": "ethereum",
  "txHash": "0x...",
  "recipientAddress": "0x...",
  "recipientName": "punk"
}
```

For Cellframe:
```json
{
  "type": "token_transfer",
  "amount": "100",
  "token": "CELL",
  "network": "Cellframe",
  "chain": "cellframe",
  "txHash": "...",
  "recipientAddress": "...",
  "recipientName": "punk"
}
```

### No Changes Needed
- `_TransferBubble` — Already reads `token`, `chain`, `network` dynamically
- C engine `dna_engine_send_tokens()` — Already supports all chain/token combinations

## Out of Scope
- Cellframe USDC contract verification
- Custom token import
- DEX/swap integration
- Old message backward compatibility
