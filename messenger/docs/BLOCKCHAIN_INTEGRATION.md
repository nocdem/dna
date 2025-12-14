# Blockchain Integration Guide

## Overview

DNA Messenger uses a modular blockchain architecture. Each blockchain is a self-contained module that implements the `blockchain_ops_t` interface.

## Architecture

```
blockchain/
├── blockchain.h              # Common interface
├── blockchain_registry.c     # Chain registration
├── ethereum/
│   ├── eth_chain.c           # blockchain_ops_t implementation
│   ├── eth_tx.c              # Transaction building/signing
│   ├── eth_rpc.c             # JSON-RPC client
│   ├── eth_erc20.c           # ERC-20 token support (USDT, USDC)
│   └── eth_wallet.h          # Wallet utilities
├── tron/
│   ├── trx_chain.c           # blockchain_ops_t implementation
│   ├── trx_tx.c              # Transaction building/signing
│   ├── trx_rpc.c             # TronGrid API client
│   ├── trx_trc20.c           # TRC-20 token support (USDT, USDC)
│   ├── trx_base58.c          # Base58Check encoding
│   └── trx_wallet.h          # Wallet utilities
├── solana/
│   ├── sol_chain.c           # blockchain_ops_t implementation
│   ├── sol_tx.c              # Transaction building/signing
│   ├── sol_rpc.c             # JSON-RPC client
│   └── sol_wallet.c          # Wallet utilities (Ed25519)
└── cellframe/
    ├── cell_chain.c          # blockchain_ops_t implementation
    ├── cellframe_tx_builder.c
    ├── cellframe_rpc.c
    └── cellframe_wallet.c
```

## Supported Tokens

### Ethereum (ERC-20)

| Token | Contract Address | Decimals |
|-------|-----------------|----------|
| USDT | `0xdAC17F958D2ee523a2206206994597C13D831ec7` | 6 |
| USDC | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | 6 |

### TRON (TRC-20)

| Token | Contract Address | Decimals |
|-------|-----------------|----------|
| USDT | `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` | 6 |
| USDC | `TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8` | 6 |
| USDD | `TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn` | 18 |

### Using Token Support

```c
#include "blockchain/blockchain.h"

// Get ETH chain
const blockchain_ops_t *eth = blockchain_get("ethereum");

// Get native ETH balance
char balance[64];
eth->get_balance("0x...", NULL, balance, sizeof(balance));

// Get USDT balance (pass token symbol)
eth->get_balance("0x...", "USDT", balance, sizeof(balance));

// Send USDT
eth->send(from, to, "100.0", "USDT", privkey, 32,
          BLOCKCHAIN_FEE_NORMAL, txhash, sizeof(txhash));

// Get TRON chain
const blockchain_ops_t *trx = blockchain_get("tron");

// Get TRC-20 USDT balance
trx->get_balance("T...", "USDT", balance, sizeof(balance));

// Send TRC-20 USDT
trx->send(from, to, "100.0", "USDT", privkey, 32,
          BLOCKCHAIN_FEE_NORMAL, txhash, sizeof(txhash));
```

## Adding a New Blockchain

### Step 1: Create Directory Structure

```bash
mkdir -p blockchain/bitcoin
```

### Step 2: Add Chain Type

Edit `blockchain/blockchain.h`:

```c
typedef enum {
    BLOCKCHAIN_TYPE_UNKNOWN = 0,
    BLOCKCHAIN_TYPE_ETHEREUM,
    BLOCKCHAIN_TYPE_CELLFRAME,
    BLOCKCHAIN_TYPE_BITCOIN,      // Add your chain
    BLOCKCHAIN_TYPE_SOLANA,
} blockchain_type_t;
```

### Step 3: Implement blockchain_ops_t

Create `blockchain/bitcoin/btc_chain.c`:

```c
#include "../blockchain.h"
#include <string.h>
#include <stdio.h>

#define LOG_TAG "BTC_CHAIN"
#include "crypto/utils/qgp_log.h"

/* ============================================================================
 * INTERFACE IMPLEMENTATIONS
 * ============================================================================ */

static int btc_chain_init(void) {
    QGP_LOG_INFO(LOG_TAG, "Bitcoin chain initialized");
    return 0;
}

static void btc_chain_cleanup(void) {
    QGP_LOG_INFO(LOG_TAG, "Bitcoin chain cleanup");
}

static int btc_chain_get_balance(
    const char *address,
    const char *token,          // NULL for native BTC
    char *balance_out,
    size_t balance_out_size
) {
    // TODO: Implement via Bitcoin RPC or API
    // Return balance as decimal string (e.g., "0.00123456")
    if (balance_out && balance_out_size > 0) {
        snprintf(balance_out, balance_out_size, "0");
    }
    return 0;
}

static int btc_chain_estimate_fee(
    blockchain_fee_speed_t speed,
    uint64_t *fee_out,          // In satoshis
    uint64_t *gas_price_out     // sat/vB for Bitcoin
) {
    // TODO: Implement fee estimation
    // Use mempool API or Bitcoin Core estimatesmartfee
    uint64_t sat_per_vb;
    switch (speed) {
        case BLOCKCHAIN_FEE_SLOW:
            sat_per_vb = 5;   // ~1 hour
            break;
        case BLOCKCHAIN_FEE_FAST:
            sat_per_vb = 50;  // Next block
            break;
        default:
            sat_per_vb = 20;  // ~30 min
            break;
    }

    if (gas_price_out) *gas_price_out = sat_per_vb;
    if (fee_out) *fee_out = sat_per_vb * 250; // Typical tx size

    return 0;
}

static int btc_chain_send(
    const char *from_address,
    const char *to_address,
    const char *amount,         // BTC as decimal string
    const char *token,          // NULL for BTC
    const uint8_t *private_key,
    size_t private_key_len,
    blockchain_fee_speed_t fee_speed,
    char *txhash_out,
    size_t txhash_out_size
) {
    // TODO: Implement Bitcoin transaction
    // 1. Get UTXOs for from_address
    // 2. Build transaction
    // 3. Sign with private key
    // 4. Broadcast via RPC/API
    QGP_LOG_ERROR(LOG_TAG, "btc_chain_send not yet implemented");
    return -1;
}

static int btc_chain_get_tx_status(
    const char *txhash,
    blockchain_tx_status_t *status_out
) {
    // TODO: Check transaction confirmations
    if (status_out) {
        *status_out = BLOCKCHAIN_TX_PENDING;
    }
    return 0;
}

static bool btc_chain_validate_address(const char *address) {
    if (!address) return false;

    size_t len = strlen(address);

    // Legacy P2PKH (starts with 1)
    if (address[0] == '1' && len >= 26 && len <= 35) return true;

    // P2SH (starts with 3)
    if (address[0] == '3' && len >= 26 && len <= 35) return true;

    // Bech32 (starts with bc1)
    if (strncmp(address, "bc1", 3) == 0 && len >= 42 && len <= 62) return true;

    return false;
}

/* ============================================================================
 * REGISTRATION
 * ============================================================================ */

static const blockchain_ops_t btc_ops = {
    .name = "bitcoin",
    .type = BLOCKCHAIN_TYPE_BITCOIN,
    .init = btc_chain_init,
    .cleanup = btc_chain_cleanup,
    .get_balance = btc_chain_get_balance,
    .estimate_fee = btc_chain_estimate_fee,
    .send = btc_chain_send,
    .get_tx_status = btc_chain_get_tx_status,
    .validate_address = btc_chain_validate_address,
    .user_data = NULL,
};

/* Auto-register on library load */
__attribute__((constructor))
static void btc_chain_register(void) {
    blockchain_register(&btc_ops);
}
```

### Step 4: Add Supporting Files

Create additional files as needed:

- `btc_rpc.c` - Bitcoin RPC/API client
- `btc_tx.c` - Transaction building
- `btc_wallet.c` - Wallet utilities

### Step 5: Update CMakeLists.txt

Add your files to `CMakeLists.txt`:

```cmake
blockchain/bitcoin/btc_chain.c              # Bitcoin blockchain_ops implementation
blockchain/bitcoin/btc_rpc.c                # Bitcoin RPC client
blockchain/bitcoin/btc_tx.c                 # Bitcoin transaction building
```

### Step 6: Build and Test

```bash
cd build
cmake ..
make -j4 dna_lib
```

## Interface Reference

### blockchain_ops_t

| Function | Required | Description |
|----------|----------|-------------|
| `init` | No | Called on startup |
| `cleanup` | No | Called on shutdown |
| `get_balance` | Yes | Get address balance |
| `estimate_fee` | Yes | Estimate transaction fee |
| `send` | Yes | Send tokens |
| `get_tx_status` | Yes | Check transaction status |
| `validate_address` | Yes | Validate address format |

### Fee Speed Presets

| Speed | Description | Typical Use |
|-------|-------------|-------------|
| `BLOCKCHAIN_FEE_SLOW` | Cheaper, slower | Non-urgent |
| `BLOCKCHAIN_FEE_NORMAL` | Balanced | Default |
| `BLOCKCHAIN_FEE_FAST` | Higher fee, faster | Time-sensitive |

### Transaction Status

| Status | Description |
|--------|-------------|
| `BLOCKCHAIN_TX_PENDING` | In mempool |
| `BLOCKCHAIN_TX_SUCCESS` | Confirmed |
| `BLOCKCHAIN_TX_FAILED` | Failed/reverted |
| `BLOCKCHAIN_TX_NOT_FOUND` | Not found |

## Using the Interface

```c
#include "blockchain/blockchain.h"

// Get chain by name
const blockchain_ops_t *eth = blockchain_get("ethereum");
const blockchain_ops_t *btc = blockchain_get("bitcoin");

// Get chain by type
const blockchain_ops_t *chain = blockchain_get_by_type(BLOCKCHAIN_TYPE_ETHEREUM);

// Estimate fee
uint64_t fee, gas_price;
chain->estimate_fee(BLOCKCHAIN_FEE_NORMAL, &fee, &gas_price);

// Validate address
if (chain->validate_address("0x...")) {
    // Valid
}

// Send transaction
char txhash[128];
chain->send(from, to, "0.1", NULL, privkey, 32,
            BLOCKCHAIN_FEE_NORMAL, txhash, sizeof(txhash));
```

## Best Practices

1. **Error Handling**: Always return 0 on success, -1 on error
2. **Logging**: Use `QGP_LOG_*` macros with chain-specific LOG_TAG
3. **Thread Safety**: Keep operations stateless where possible
4. **Memory**: Don't allocate in ops functions; use caller-provided buffers
5. **Amounts**: Use decimal strings for amounts to avoid precision issues

## Wallet Integration

Wallets are managed separately in `blockchain/blockchain_wallet.c`. After adding a chain, update the wallet system to support it.
