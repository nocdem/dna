# Wallet Token Grouping — Multi-chain Balance Aggregation

**Date:** 2026-03-16
**Status:** PLANNED
**Priority:** HIGH

## Problem

USDT exists on 3 chains (Ethereum, Solana, Tron). Currently shows as 3 separate entries:
- USDT (Ethereum): 9.51
- USDT (Solana): 3.43
- USDT (Tron): 0.00

User sees 3 lines for the same token. Confusing.

## Solution

### Wallet List View (Level 1)
```
USDT                    $12.94
  Total across 3 chains
  
ETH                     $0.01
  Ethereum

CPUNK                   100.0
  Backbone

CELL                    6.0
  Backbone
```

- Group tokens by **symbol** (USDT, USDC, etc.)
- Show **total balance** across all chains
- Single row per token
- Subtitle: "Total across N chains" if multi-chain, else chain name

### Token Detail View (Level 2) — tap on grouped token
```
USDT — Total: $12.94

  Ethereum    9.51 USDT
  Solana      3.43 USDT  
  Tron        0.00 USDT

  [Tap chain for TX history]
```

- Shows per-chain breakdown
- Each chain row is tappable → goes to TX history for that chain

### TX History View (Level 3) — tap on chain
```
USDT on Ethereum — 9.51 USDT

  2026-03-15  +5.00  from 0x3a2...
  2026-03-14  -1.50  to 0x7b4...
  ...
```

- Standard transaction history, filtered by token + chain

## Flutter Implementation

### Data Model
```dart
class GroupedToken {
  final String symbol;
  final String name;        // "Tether USD"
  final double totalBalance;
  final double totalUsdValue;
  final List<ChainBalance> chains;
}

class ChainBalance {
  final String network;     // "Ethereum", "Solana", "Tron"
  final int walletIndex;    // 0, 1, 2
  final double balance;
  final String tokenAddress;
}
```

### Provider
```dart
final groupedTokensProvider = Provider<List<GroupedToken>>((ref) {
  // Read all wallet balances
  // Group by token symbol
  // Sum balances across chains
  // Sort by USD value descending
});
```

### Navigation Flow
```
WalletScreen (grouped list)
  → TokenDetailScreen (per-chain breakdown)  [NEW]
    → TransactionHistoryScreen (existing, per chain)
```

### Token Grouping Rules
- Match by **symbol** (case-insensitive): USDT, USDC
- Native tokens are NOT grouped (ETH, SOL, TRX are separate)
- CPUNK/CELL/NYS are single-chain (Backbone), no grouping needed
- If token exists on only 1 chain → skip detail screen, go direct to TX history

## Files to Modify
- `lib/screens/wallet/wallet_screen.dart` — grouped list view
- `lib/screens/wallet/token_detail_screen.dart` — NEW: per-chain breakdown
- `lib/providers/wallet_provider.dart` — grouping logic
- `lib/widgets/token_tile.dart` — new grouped tile widget

## Effort
~2-3 days (Flutter only, no C changes needed)
