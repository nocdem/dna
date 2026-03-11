# Token Transfer Verification Design

**Date:** 2026-03-11
**Status:** Approved

## Overview

When a token transfer is sent via DM (currently CPUNK/Backbone, future: ETH, SOL, TRON), both sender and receiver independently verify the transaction status from the blockchain and display it visually on the transfer bubble.

## Message Type

Replace `cpunk_transfer` with `token_transfer` (clean switch, no backward compatibility):

```json
{
  "type": "token_transfer",
  "amount": "100",
  "token": "CPUNK",
  "network": "Backbone",
  "chain": "cellframe",
  "txHash": "ABC123...",
  "recipientAddress": "...",
  "recipientName": "punk"
}
```

The `chain` field identifies which `blockchain_ops_t` to use for verification. Supports future chains without code changes.

## Architecture

```
SENDER                                    RECEIVER
------                                    --------
1. Send tokens (existing flow)
2. Send chat message: {"type":"token_transfer", ...}
3. TransferBubble renders (ORANGE=pending)
                                          4. Receives message
                                          5. TransferBubble renders (ORANGE=pending)

Both sides independently:
6. On bubble render -> check transfer_verifications table
7. If no entry or status=pending -> call dna_engine_get_tx_status()
8. Engine calls blockchain_ops_t.get_tx_status(txHash) -> public RPC
9. Store result in transfer_verifications table
10. Update bubble border: GREEN=verified, RED=denied

Manual: Tap bubble -> force re-check regardless of cached status
```

No new messages sent between users. Each device verifies for itself.

## C Engine Layer

New function in `dna_engine_wallet.c` (existing module):

```c
dna_request_id_t dna_engine_get_tx_status(
    dna_engine_t *engine,
    const char *tx_hash,
    const char *chain,        // "cellframe", "ethereum", "solana", "tron"
    dna_tx_status_callback_t cb,
    void *user_data
);
```

New task type: `TASK_GET_TX_STATUS`

Handler flow:
1. Check `transfer_verifications` table for cached result
2. If final status (verified/denied), return cached
3. If pending or no entry, call `blockchain_ops_t.get_tx_status()`
4. Update cache table with result
5. Return status via callback

Callback type:
```c
typedef void (*dna_tx_status_callback_t)(
    dna_request_id_t request_id,
    const char *error,
    const char *tx_hash,
    int status,          // 0=pending, 1=verified, 2=denied
    void *user_data
);
```

## Database Layer

New table in messages DB (C-side, accessible by both Flutter and CLI):

```sql
CREATE TABLE IF NOT EXISTS transfer_verifications (
    tx_hash TEXT PRIMARY KEY,
    chain TEXT NOT NULL,
    status INTEGER NOT NULL DEFAULT 0,
    last_checked INTEGER NOT NULL
);
```

Status values:
- 0 = pending
- 1 = verified (blockchain confirmed)
- 2 = denied (not found / failed)

## FFI Bridge

New Dart binding:

```dart
Future<int> getTxStatus(String txHash, String chain) { ... }
```

Returns status code matching C-side values.

## Flutter UI

- `_TransferBubble` changes from `StatelessWidget` to `StatefulWidget`
- `initState` triggers `dna_engine_get_tx_status(txHash, chain)`
- Border color reflects status:
  - Orange = pending
  - Green = verified
  - Red = denied
- Status icon next to tx hash (clock/check/x)
- Tap bubble to force re-check (bypasses cache)
- `_parseTransferData()` detects `"type": "token_transfer"` instead of `"cpunk_transfer"`

## Verification Behavior

- **First display**: No cache -> query blockchain -> cache result
- **Still pending**: Every render re-queries blockchain
- **Final state (verified/denied)**: Return cached, no re-query
- **Manual refresh**: Tap to force re-check regardless of cache
- **App restart**: On render, reads cache -> if pending, re-queries

## Scope

- Uses existing `blockchain_ops_t.get_tx_status` interface
- Cellframe: fully implemented (public RPC at rpc.cellframe.net)
- ETH/SOL/TRON: currently stubbed, will work when implemented
- No new engine module needed
- No DB migration on messages table
- CLI can use same engine API
