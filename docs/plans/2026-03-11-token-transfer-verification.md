# Token Transfer Verification Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Both sender and receiver independently verify token transfer transactions from the blockchain and display status visually (orange=pending, green=verified, red=denied).

**Architecture:** New `TASK_GET_TX_STATUS` task in existing wallet engine module. Cache table `transfer_verifications` in wallet_cache.db. Flutter `_TransferBubble` becomes StatefulWidget with async verification on render. Message type changes from `cpunk_transfer` to `token_transfer`.

**Tech Stack:** C (engine + SQLite), Dart/Flutter (FFI + UI), Cellframe public RPC

**Design Doc:** `docs/plans/2026-03-11-token-transfer-verification-design.md`

---

### Task 1: Add `transfer_verifications` table to wallet cache DB

**Files:**
- Modify: `messenger/database/wallet_cache.c` (add table to `create_schema()`)
- Modify: `messenger/database/wallet_cache.h` (add new function declarations)

**Step 1: Add table creation to `create_schema()` in `wallet_cache.c`**

After the existing `transactions_sql` block (~line 63), add:

```c
    const char *verifications_sql =
        "CREATE TABLE IF NOT EXISTS transfer_verifications ("
        "    tx_hash      TEXT PRIMARY KEY,"
        "    chain        TEXT NOT NULL,"
        "    status       INTEGER NOT NULL DEFAULT 0,"
        "    last_checked INTEGER NOT NULL"
        ");";

    rc = sqlite3_exec(g_db, verifications_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create verifications schema: %s", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
```

**Step 2: Add cache lookup function to `wallet_cache.c`**

```c
int wallet_cache_get_tx_status(const char *tx_hash, int *status_out) {
    if (!g_db || !tx_hash || !status_out) return -1;

    const char *sql = "SELECT status FROM transfer_verifications WHERE tx_hash = ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, tx_hash, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *status_out = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;
}
```

**Step 3: Add cache save function to `wallet_cache.c`**

```c
int wallet_cache_save_tx_status(const char *tx_hash, const char *chain, int status) {
    if (!g_db || !tx_hash || !chain) return -1;

    const char *sql =
        "INSERT OR REPLACE INTO transfer_verifications "
        "(tx_hash, chain, status, last_checked) VALUES (?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, tx_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, chain, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, status);
    sqlite3_bind_int64(stmt, 4, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}
```

**Step 4: Add declarations to `wallet_cache.h`**

```c
#define TX_STATUS_PENDING   0
#define TX_STATUS_VERIFIED  1
#define TX_STATUS_DENIED    2

int wallet_cache_get_tx_status(const char *tx_hash, int *status_out);
int wallet_cache_save_tx_status(const char *tx_hash, const char *chain, int status);
```

**Step 5: Build and verify**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`

Expected: Clean build, no warnings.

**Step 6: Commit**

---

### Task 2: Add `TASK_GET_TX_STATUS` to engine internals

**Files:**
- Modify: `messenger/src/api/dna_engine_internal.h` (add task type, params, callback, handler declaration)

**Step 1: Add task type**

In the task enum (~line 115, after `TASK_GET_CACHED_TRANSACTIONS`), add:

```c
    TASK_GET_TX_STATUS,
```

**Step 2: Add task params**

In the `dna_task_params_t` union (after the `get_transactions` struct), add:

```c
    struct {
        char tx_hash[256];
        char chain[32];
    } get_tx_status;
```

**Step 3: Add callback type to union**

In the `dna_task_callback_t` union, add:

```c
    dna_tx_status_cb tx_status;
```

**Step 4: Add handler declaration**

After the wallet handler declarations (~line 820), add:

```c
void dna_handle_get_tx_status(dna_engine_t *engine, dna_task_t *task);
```

**Step 5: Build and verify**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`

**Step 6: Commit**

---

### Task 3: Add public API and callback typedef to `dna_engine.h`

**Files:**
- Modify: `messenger/include/dna/dna_engine.h` (add callback typedef + public API function)

**Step 1: Add callback typedef**

After the `dna_send_tokens_cb` typedef (~line 358), add:

```c
/**
 * Transaction status callback
 * status: 0=pending, 1=verified, 2=denied
 * tx_hash echoed back for matching
 */
typedef void (*dna_tx_status_cb)(
    dna_request_id_t request_id,
    const char *error,
    const char *tx_hash,
    int status,
    void *user_data
);
```

**Step 2: Add public API function declaration**

After `dna_engine_send_tokens` (~line 2122), add:

```c
/**
 * Get transaction verification status from blockchain
 *
 * Checks cache first. If cached as final (verified/denied), returns immediately.
 * If pending or uncached, queries blockchain via the chain's get_tx_status op.
 *
 * @param engine    Engine instance
 * @param tx_hash   Transaction hash to verify
 * @param chain     Blockchain name ("cellframe", "ethereum", "solana", "tron")
 * @param callback  Called with status result
 * @param user_data User data for callback
 * @return          Request ID (0 on immediate error)
 */
DNA_API dna_request_id_t dna_engine_get_tx_status(
    dna_engine_t *engine,
    const char *tx_hash,
    const char *chain,
    dna_tx_status_cb callback,
    void *user_data
);
```

**Step 3: Build and verify**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`

**Step 4: Commit**

---

### Task 4: Implement handler in `dna_engine_wallet.c` + dispatch in `dna_engine.c`

**Files:**
- Modify: `messenger/src/api/engine/dna_engine_wallet.c` (add handler + public API wrapper)
- Modify: `messenger/src/api/dna_engine.c` (add dispatch case)

**Step 1: Add handler to `dna_engine_wallet.c`**

At the end of the file (before the public API wrappers section), add:

```c
void dna_handle_get_tx_status(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;
    const char *tx_hash = task->params.get_tx_status.tx_hash;
    const char *chain = task->params.get_tx_status.chain;

    /* Check cache first */
    int cached_status = -1;
    if (wallet_cache_get_tx_status(tx_hash, &cached_status) == 0) {
        if (cached_status == TX_STATUS_VERIFIED || cached_status == TX_STATUS_DENIED) {
            if (task->callback.tx_status) {
                task->callback.tx_status(task->request_id, NULL, tx_hash,
                                         cached_status, task->user_data);
            }
            return;
        }
    }

    /* Look up blockchain ops by chain name */
    const blockchain_ops_t *ops = blockchain_get(chain);
    if (!ops || !ops->get_tx_status) {
        QGP_LOG_ERROR(LOG_TAG, "No get_tx_status for chain: %s", chain);
        wallet_cache_save_tx_status(tx_hash, chain, TX_STATUS_DENIED);
        if (task->callback.tx_status) {
            task->callback.tx_status(task->request_id, "unsupported chain",
                                     tx_hash, TX_STATUS_DENIED, task->user_data);
        }
        return;
    }

    /* Query blockchain */
    blockchain_tx_status_t bc_status = BLOCKCHAIN_TX_PENDING;
    int ret = ops->get_tx_status(tx_hash, &bc_status);

    int status;
    if (ret != 0) {
        status = TX_STATUS_DENIED;
    } else {
        switch (bc_status) {
            case BLOCKCHAIN_TX_SUCCESS:
                status = TX_STATUS_VERIFIED;
                break;
            case BLOCKCHAIN_TX_FAILED:
            case BLOCKCHAIN_TX_NOT_FOUND:
                status = TX_STATUS_DENIED;
                break;
            case BLOCKCHAIN_TX_PENDING:
            default:
                status = TX_STATUS_PENDING;
                break;
        }
    }

    /* Cache result */
    wallet_cache_save_tx_status(tx_hash, chain, status);

    if (task->callback.tx_status) {
        task->callback.tx_status(task->request_id, NULL, tx_hash,
                                 status, task->user_data);
    }
}
```

**Step 2: Add public API wrapper to `dna_engine_wallet.c`**

After the `dna_engine_send_tokens` wrapper, add:

```c
dna_request_id_t dna_engine_get_tx_status(
    dna_engine_t *engine,
    const char *tx_hash,
    const char *chain,
    dna_tx_status_cb callback,
    void *user_data
) {
    if (!engine || !tx_hash || !chain) return 0;

    dna_task_params_t params = {0};
    strncpy(params.get_tx_status.tx_hash, tx_hash, sizeof(params.get_tx_status.tx_hash) - 1);
    strncpy(params.get_tx_status.chain, chain, sizeof(params.get_tx_status.chain) - 1);

    return dna_submit_task(engine, TASK_GET_TX_STATUS, &params, cb, user_data);
}
```

**IMPORTANT:** Check how `dna_engine_send_tokens` passes the callback to `dna_submit_task` and follow the same pattern exactly. The 4th argument cast may need adjustment.

**Step 3: Add dispatch case in `dna_engine.c`**

In the task dispatch switch (~line 1002, after `TASK_SEND_TOKENS`), add:

```c
        case TASK_GET_TX_STATUS:
            dna_handle_get_tx_status(engine, task);
            break;
```

**Step 4: Verify includes in `dna_engine_wallet.c`**

Ensure these are included (check existing includes first):

```c
#include "../../blockchain/blockchain.h"
#include "../../database/wallet_cache.h"
```

**Step 5: Build and verify**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`

Expected: Clean build, no warnings, no undefined symbols.

**Step 6: Commit**

---

### Task 5: Add FFI bindings in Dart

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/ffi/dna_bindings.dart` (add callback typedef + binding)
- Modify: `messenger/dna_messenger_flutter/lib/ffi/dna_engine.dart` (add Dart wrapper)

**Step 1: Add callback typedef to `dna_bindings.dart`**

After `DnaSendTokensCb` (~line 820), add:

```dart
/// TX status callback - Native
typedef DnaTxStatusCbNative = Void Function(
  Uint64 request_id,
  Pointer<Utf8> error,
  Pointer<Utf8> tx_hash,
  Int32 status,
  Pointer<Void> user_data,
);
typedef DnaTxStatusCb = NativeFunction<DnaTxStatusCbNative>;
```

**Step 2: Add binding function to `DnaBindings` class in `dna_bindings.dart`**

After `dna_engine_send_tokens` (~line 2420), add:

```dart
  late final _dna_engine_get_tx_status = _lib.lookupFunction<
      Uint64 Function(
          Pointer<dna_engine_t>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<DnaTxStatusCb>,
          Pointer<Void>),
      int Function(
          Pointer<dna_engine_t>,
          Pointer<Utf8>,
          Pointer<Utf8>,
          Pointer<DnaTxStatusCb>,
          Pointer<Void>)>('dna_engine_get_tx_status');

  int dna_engine_get_tx_status(
    Pointer<dna_engine_t> engine,
    Pointer<Utf8> tx_hash,
    Pointer<Utf8> chain,
    Pointer<DnaTxStatusCb> callback,
    Pointer<Void> user_data,
  ) {
    return _dna_engine_get_tx_status(engine, tx_hash, chain, callback, user_data);
  }
```

**Step 3: Add Dart wrapper to `dna_engine.dart`**

After the `sendTokens` method (~line 2970), add:

```dart
  /// Get transaction verification status from blockchain
  /// Returns status: 0=pending, 1=verified, 2=denied
  Future<int> getTxStatus({
    required String txHash,
    required String chain,
  }) async {
    final completer = Completer<int>();
    final localId = _nextLocalId++;

    final txHashPtr = txHash.toNativeUtf8();
    final chainPtr = chain.toNativeUtf8();

    void onComplete(int requestId, Pointer<Utf8> error, Pointer<Utf8> txHashResult, int status, Pointer<Void> userData) {
      calloc.free(txHashPtr);
      calloc.free(chainPtr);

      if (error != nullptr) {
        final errorStr = error.toDartString();
        completer.completeError(DnaEngineException(-1, errorStr));
      } else {
        completer.complete(status);
      }
      _cleanupRequest(localId);
    }

    final callback = NativeCallable<DnaTxStatusCbNative>.listener(onComplete);
    _pendingRequests[localId] = _PendingRequest(callback: callback);

    final requestId = _bindings.dna_engine_get_tx_status(
      _engine,
      txHashPtr.cast(),
      chainPtr.cast(),
      callback.nativeFunction.cast(),
      nullptr,
    );

    if (requestId == 0) {
      calloc.free(txHashPtr);
      calloc.free(chainPtr);
      _cleanupRequest(localId);
      throw DnaEngineException(-1, 'Failed to submit tx status request');
    }

    return completer.future;
  }
```

**Step 4: Build Flutter**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`

Expected: Clean build.

**Step 5: Commit**

---

### Task 6: Change message type from `cpunk_transfer` to `token_transfer`

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/screens/chat/chat_screen.dart`

**Step 1: Update `_parseTransferData()` method**

Change the type check (~line 2892):

```dart
// Before:
if (data['type'] == 'cpunk_transfer') {
// After:
if (data['type'] == 'token_transfer') {
```

**Step 2: Update the transfer message JSON in send flow**

Change the JSON construction (~line 2367):

```dart
final transferData = jsonEncode({
  'type': 'token_transfer',
  'amount': amountStr,
  'token': 'CPUNK',
  'network': 'Backbone',
  'chain': 'cellframe',
  'txHash': txHash,
  'recipientAddress': _resolvedAddress,
  'recipientName': widget.contact.displayName,
});
```

**Step 3: Build Flutter**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`

**Step 4: Commit**

---

### Task 7: Convert `_TransferBubble` to StatefulWidget with verification

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/screens/chat/chat_screen.dart`

**Step 1: Replace `_TransferBubble` class**

Replace the entire `_TransferBubble` class (~lines 2841-3009) with a StatefulWidget that:

1. Calls `engine.getTxStatus(txHash, chain)` in `initState`
2. Shows orange border while pending, green when verified, red when denied
3. Shows a status icon (clock/check/xmark) and text next to the tx hash
4. On tap of the entire bubble, re-verifies (force re-check)
5. Shows a small `CircularProgressIndicator` while actively verifying

Key implementation notes:
- Access the engine via `ProviderScope.containerOf(context).read(engineProvider).valueOrNull`
- The border replaces the conditional `isOutgoing ? null : Border.all(...)` with `Border.all(color: borderColor, width: 2)` for all bubbles
- Preserve all existing UI elements (arrow icon, amount, tx hash copy, timestamp, message status)
- Add verification status row between tx hash and timestamp

**Step 2: Build Flutter**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`

**Step 3: Commit**

---

### Task 8: Update documentation and function references

**Files:**
- Modify: `messenger/docs/functions/public-api.md` (add `dna_engine_get_tx_status`)
- Modify: `messenger/docs/functions/blockchain.md` (document cache functions)
- Modify: `messenger/docs/FLUTTER_UI.md` (document TransferBubble verification)

**Step 1: Add to `public-api.md` wallet section**

```markdown
| `dna_request_id_t dna_engine_get_tx_status(engine, tx_hash, chain, cb, user_data)` | Get TX verification status from blockchain (cached) |
```

**Step 2: Add to `blockchain.md`**

Add Transfer Verification Cache section with `wallet_cache_get_tx_status` and `wallet_cache_save_tx_status`.

**Step 3: Update `FLUTTER_UI.md`**

Document TransferBubble verification behavior.

**Step 4: Commit**

---

### Task 9: Build all, bump versions, final commit

**Step 1: Full C build**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`

**Step 2: Full Flutter build**

Run: `cd messenger/dna_messenger_flutter && flutter build linux`

**Step 3: Run tests**

Run: `cd messenger/build && ctest --output-on-failure`

**Step 4: Bump versions**

- C library: bump PATCH in `messenger/include/dna/version.h`
- Flutter: bump PATCH + versionCode in `messenger/dna_messenger_flutter/pubspec.yaml`

**Step 5: Final commit with version**

---

## Task Summary

| Task | Description | Layer |
|------|-------------|-------|
| 1 | `transfer_verifications` table + cache functions | C / Database |
| 2 | `TASK_GET_TX_STATUS` in engine internals | C / Engine |
| 3 | Public API + callback typedef in `dna_engine.h` | C / API |
| 4 | Handler implementation + dispatch | C / Engine |
| 5 | FFI bindings (Dart) | Flutter / FFI |
| 6 | Message type `cpunk_transfer` to `token_transfer` | Flutter / UI |
| 7 | `_TransferBubble` StatefulWidget with verification | Flutter / UI |
| 8 | Documentation updates | Docs |
| 9 | Build all, test, bump versions | Release |
