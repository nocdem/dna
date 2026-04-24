> **ARCHIVED 2026-04-24** — DNAC CLI was merged into the main messenger CLI. There is no standalone `dnac-cli`; commands live in `dna-connect-cli dna <verb>` (handlers in `messenger/cli/cli_dna_chain*.c`). This doc (v0.7.1, 2026-01-24) predates that move. Use `dna-connect-cli dna --help` for current commands.

# DNAC CLI Commands Reference

**Version:** v0.7.1 | **Last Updated:** 2026-01-24

---

## Overview

`dnac-cli` is the command-line interface for DNAC (Post-Quantum Zero-Knowledge Cash). It provides wallet management, identity lookup, and transaction capabilities over the DNA Connect DHT network.

### Installation

The CLI is built alongside the DNAC library:

```bash
cd /opt/dna/dnac/build
cmake .. && make -j$(nproc)
./dnac-cli --help
```

### Prerequisites

- A DNA Connect identity must exist (created via `dna-cli create <name>`)
- The identity is loaded from `~/.dna/` by default

---

## Command Reference

### Identity & Info Commands

#### `info` - Show Wallet Info and Status

Displays comprehensive wallet information including version, address, DHT connection status, and balance.

```bash
dnac-cli info
```

**Output:**
```
DNAC Wallet Info
================
Version:     0.1.28
Address:     3cbba8d8bf0c36033fd441e9387af846...
Full:        3cbba8d8bf0c36033fd441e9387af84643ccebc586ef6f307d6993d406e041ca83165e1dfb2f94c88a60d67a3557094ea6481a503763579252d93a54409b2065
DHT:         Connected
Balance:     0.000026
```

**Fields:**
| Field | Description |
|-------|-------------|
| Version | DNAC library version |
| Address | Truncated wallet address (fingerprint) |
| Full | Complete 128-character fingerprint |
| DHT | Connection status to DHT network |
| Balance | Confirmed wallet balance |

---

#### `address` - Show Wallet Address

Outputs only the wallet address (fingerprint) with no formatting. Designed for scripting and piping.

```bash
dnac-cli address
```

**Output:**
```
3cbba8d8bf0c36033fd441e9387af84643ccebc586ef6f307d6993d406e041ca83165e1dfb2f94c88a60d67a3557094ea6481a503763579252d93a54409b2065
```

**Use Cases:**
```bash
# Store address in variable
MY_ADDRESS=$(dnac-cli address)

# Copy to clipboard (Linux)
dnac-cli address | xclip -selection clipboard

# Send to self
dnac-cli send $(dnac-cli address) 1000000
```

---

#### `query <name|fingerprint>` - Lookup Identity

Resolves a registered name to its fingerprint via DHT lookup. Also accepts fingerprints directly for validation.

```bash
# Lookup by name
dnac-cli query nocdem

# Lookup by fingerprint (128 hex chars)
dnac-cli query 7a145ade5e99b16fbf04f23e590928a6cd21d1d38c39a8719924ec381b9d1b2123d999b4a7c6f459fe631f1595ae50a49c67918a870829b972eb2d95287ed2fd
```

**Output (name lookup):**
```
Looking up name: nocdem

Identity Found:
  Fingerprint: 7a145ade5e99b16fbf04f23e590928a6cd21d1d38c39a8719924ec381b9d1b2123d999b4a7c6f459fe631f1595ae50a49c67918a870829b972eb2d95287ed2fd
```

**Auto-Detection Logic:**
- Input is exactly 128 lowercase hex characters → treated as fingerprint
- Otherwise → treated as name, resolved via DHT

**Error Cases:**
| Error | Meaning |
|-------|---------|
| `Name 'xxx' not registered` | Name exists but no owner registered |
| `Lookup failed` | DHT network error |

---

### Wallet Commands

#### `balance` - Show Wallet Balance

```bash
dnac-cli balance
```

**Output:**
```
DNAC Wallet Balance
-------------------
Confirmed:  0.000026
Pending:    0
Locked:     0
UTXOs:      3
```

---

#### `utxos` - List Unspent Transaction Outputs

```bash
dnac-cli utxos
```

**Output:**
```
DNAC UTXOs (3 total)
INDEX   AMOUNT            STATUS      RECEIVED
------  ----------------  ----------  --------------------
0       0.000001          unspent     2026-01-20 14:32:15
1       0.000015          unspent     2026-01-21 09:45:22
2       0.00001           unspent     2026-01-22 11:20:08
```

---

#### `send <fingerprint> <amount> [memo]` - Send Payment

Sends a payment to the specified recipient with optional memo.

```bash
# Send with memo
dnac-cli send 7a145ade5e99b16fbf04f23e590928a6... 1000000 "Payment for services"

# Send without memo
dnac-cli send 7a145ade5e99b16fbf04f23e590928a6... 1000000
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| fingerprint | Recipient's 128-character fingerprint |
| amount | Amount to send (in smallest units) |
| memo | Optional memo up to 255 bytes (v0.6.0+) |

---

#### `genesis <fingerprint> <amount>` - Create Genesis Transaction

Creates the one-time genesis transaction to create initial token supply.
Requires **unanimous 3-of-3 witness authorization** (v0.5.0+).

```bash
dnac-cli genesis 3cbba8d8bf0c36033fd441e9387af846... 100000000
```

**Note:** The `mint` command is kept as an alias for backward compatibility.

---

#### `sync` - Sync Wallet from DHT

```bash
dnac-cli sync
```

---

#### `recover` - Recover Wallet from Seed

Re-scans DHT for all payments to this identity.

```bash
dnac-cli recover
```

---

### History Commands

#### `history [n]` - Show Transaction History

```bash
dnac-cli history      # All history
dnac-cli history 10   # Last 10 entries
```

---

#### `tx <hash>` - Show Transaction Details

```bash
dnac-cli tx abc123def456...
```

---

### Network Commands

#### `nodus-list` - List Witness Servers

```bash
dnac-cli nodus-list
```

---

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --version` | Show version information |
| `-d, --data-dir <path>` | Data directory (default: `~/.dna`) |

---

## Technical Details

### Wallet Address (Fingerprint)

The wallet address is a **SHA3-512 hash of the Dilithium5 public key**:
- 64 bytes = 128 hexadecimal characters
- Obtained via `dna_engine_get_fingerprint()`
- Same as DNA Connect identity fingerprint

### Name Resolution

Name-to-fingerprint resolution uses `dna_engine_lookup_name()`:

1. CLI calls `dna_engine_lookup_name(engine, name, callback, user_data)`
2. libdna queries DHT for registered name
3. Callback receives fingerprint (or empty string if name available)
4. **Important:** Callback must `free()` the returned fingerprint string

### DHT Integration (Nodus)

All commands interact with the Nodus DHT network via the `nodus_ops` API (OpenDHT has been completely removed):
- Identity loaded from local storage
- Balance/UTXOs stored in local SQLite database
- Transactions broadcast via Nodus DHT
- Name lookups query DHT name registry

### Permanent Storage (v0.1.29+)

All DHT data is stored permanently on the Nodus network via the `nodus_ops` API:
- **Payments**: Never expire (cash doesn't expire)
- **Witness attestations**: Permanent record of double-spend prevention
- **Witness announcements**: Permanent identity publication
- **Nullifier replication**: Permanent cross-witness sync

This ensures recipients can receive payments even after extended offline periods.

---

## Implementation Notes (v0.1.28)

### Files Modified

| File | Changes |
|------|---------|
| `src/cli/commands.c` | Added `dnac_cli_info()`, `dnac_cli_address()`, `dnac_cli_query()` |
| `src/cli/main.c` | Added command dispatch for info, address, query |
| `include/dnac/cli.h` | Added function declarations |
| `include/dnac/version.h` | Bumped to v0.1.28 |

### Key Implementation Details

#### Async-to-Sync Pattern

The `query` command uses pthread condition variables to convert async DHT lookup to synchronous CLI operation:

```c
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool done;
    int result;
    char fingerprint[129];
} name_lookup_ctx_t;

static void on_name_lookup(uint64_t request_id, int error,
                           const char *fingerprint, void *user_data) {
    name_lookup_ctx_t *lctx = (name_lookup_ctx_t *)user_data;
    pthread_mutex_lock(&lctx->mutex);
    lctx->result = error;
    if (fingerprint && error == 0) {
        strncpy(lctx->fingerprint, fingerprint, 128);
    }
    lctx->done = true;
    pthread_cond_signal(&lctx->cond);
    pthread_mutex_unlock(&lctx->mutex);

    /* CRITICAL: Free the strdup'd string from libdna */
    if (fingerprint) {
        free((void*)fingerprint);
    }
}
```

#### Memory Management

The `dna_engine_lookup_name()` callback receives a `strdup()`'d string that **must be freed by the callback**. This matches the pattern used in `dna-connect-cli` (see `messenger/cli/cli_commands.c`).

---

## Examples

### Complete Workflow

```bash
# Check wallet status
dnac-cli info

# Get your address for receiving payments
dnac-cli address

# Look up a contact by name
dnac-cli query alice

# Send payment
dnac-cli send $(dnac-cli query alice | grep Fingerprint | awk '{print $2}') 1000000

# Check balance after sending
dnac-cli balance

# View transaction history
dnac-cli history 5
```

### Scripting Example

```bash
#!/bin/bash
# send_to_name.sh - Send payment by name

NAME=$1
AMOUNT=$2

# Resolve name to fingerprint
FP=$(dnac-cli query "$NAME" 2>/dev/null | grep "Fingerprint:" | awk '{print $2}')

if [ -z "$FP" ]; then
    echo "Error: Could not resolve name '$NAME'"
    exit 1
fi

echo "Sending $AMOUNT to $NAME ($FP)"
dnac-cli send "$FP" "$AMOUNT"
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v0.7.1 | 2026-01-24 | BFT-anchored Merkle proofs |
| v0.7.0 | 2026-01-24 | P0 infrastructure - chain sync, Merkle proofs, confirmations |
| v0.6.0 | 2026-01-23 | Memo support, replay prevention, security gap fixes |
| v0.5.0 | 2026-01-23 | Genesis system with 3-of-3 unanimous authorization |
| v0.4.0 | 2026-01-23 | Multi-input double-spend vulnerability fix |
| v0.3.0 | 2026-01-22 | Store change UTXOs locally after send |
| v0.2.0 | 2026-01-22 | BFT consensus protocol |
| v0.1.29 | 2026-01-22 | All DHT data now permanent (cash doesn't expire) |
| v0.1.28 | 2026-01-22 | Added `info`, `address`, `query` commands |
| v0.1.27 | 2026-01-22 | Witness infrastructure deployment |
| v0.1.26 | 2026-01-21 | Mint transaction support |
