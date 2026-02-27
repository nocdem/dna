# Blockchain Functions

**Directory:** `blockchain/`

Modular blockchain interface for multi-chain wallet operations.

---

## 14. Blockchain - Common Interface

### 14.1 Blockchain Interface (`blockchain.h`)

| Function | Description |
|----------|-------------|
| `int blockchain_register(const blockchain_ops_t*)` | Register blockchain implementation |
| `const blockchain_ops_t* blockchain_get(const char*)` | Get blockchain by name |
| `const blockchain_ops_t* blockchain_get_by_type(blockchain_type_t)` | Get blockchain by type |
| `int blockchain_get_all(const blockchain_ops_t**, int)` | Get all registered blockchains |
| `int blockchain_init_all(void)` | Initialize all blockchains |
| `void blockchain_cleanup_all(void)` | Cleanup all blockchains |

### 14.2 Blockchain Wallet (`blockchain_wallet.h`)

| Function | Description |
|----------|-------------|
| `const char* blockchain_type_name(blockchain_type_t)` | Get blockchain name string |
| `const char* blockchain_type_ticker(blockchain_type_t)` | Get blockchain ticker |
| `int blockchain_create_all_wallets(const uint8_t*, const char*, const char*, const char*)` | Create all wallets from seed |
| `int blockchain_create_missing_wallets(const char*, const uint8_t*, int*)` | Create missing wallets |
| `int blockchain_create_wallet(blockchain_type_t, const uint8_t*, const char*, const char*, char*)` | Create wallet for blockchain |
| `int blockchain_list_wallets(const char*, blockchain_wallet_list_t**)` | List wallets for identity |
| `void blockchain_wallet_list_free(blockchain_wallet_list_t*)` | Free wallet list |
| `int blockchain_get_balance(blockchain_type_t, const char*, blockchain_balance_t*)` | Get wallet balance |
| `bool blockchain_validate_address(blockchain_type_t, const char*)` | Validate address format |
| `int blockchain_get_address_from_file(blockchain_type_t, const char*, char*)` | Get address from wallet file |
| `int blockchain_estimate_eth_gas(int, blockchain_gas_estimate_t*)` | Estimate ETH gas fee |
| `int blockchain_send_tokens(blockchain_type_t, const char*, const char*, const char*, const char*, int, char*)` | Send tokens |
| `int blockchain_derive_wallets_from_seed(const uint8_t*, const char*, const char*, blockchain_wallet_list_t**)` | Derive wallets on-demand |
| `int blockchain_send_tokens_with_seed(blockchain_type_t, const uint8_t*, const char*, const char*, const char*, const char*, int, char*)` | Send using derived key |

---

## 15. Blockchain - Cellframe (`blockchain/cellframe/`)

Cellframe blockchain integration with Dilithium post-quantum signatures.

### 15.1 Cellframe Wallet (`cellframe_wallet.h`)

| Function | Description |
|----------|-------------|
| `int wallet_read_cellframe_path(const char*, cellframe_wallet_t**)` | Read wallet from full path |
| `int wallet_read_cellframe(const char*, cellframe_wallet_t**)` | Read wallet from standard dir |
| `int wallet_list_cellframe(wallet_list_t**)` | List all Cellframe wallets |
| `int wallet_list_from_dna_dir(wallet_list_t**)` | List wallets from ~/.dna/wallets |
| `int wallet_list_for_identity(const char*, wallet_list_t**)` | List wallets for identity |
| `int wallet_get_address(const cellframe_wallet_t*, const char*, char*)` | Get wallet address |
| `void wallet_free(cellframe_wallet_t*)` | Free wallet structure |
| `void wallet_list_free(wallet_list_t*)` | Free wallet list |
| `const char* wallet_sig_type_name(wallet_sig_type_t)` | Get signature type name |

### 15.2 Cellframe Address (`cellframe_addr.h`)

| Function | Description |
|----------|-------------|
| `int cellframe_addr_from_pubkey(const uint8_t*, size_t, uint64_t, char*)` | Generate address from pubkey |
| `int cellframe_addr_for_identity(const char*, uint64_t, char*)` | Get address for DNA identity |
| `int cellframe_addr_to_str(const void*, char*, size_t)` | Convert binary to base58 |
| `int cellframe_addr_from_str(const char*, void*)` | Parse base58 to binary |

### 15.3 Cellframe RPC (`cellframe_rpc.h`)

| Function | Description |
|----------|-------------|
| `int cellframe_rpc_call(const cellframe_rpc_request_t*, cellframe_rpc_response_t**)` | Make RPC call |
| `int cellframe_rpc_get_tx(const char*, const char*, cellframe_rpc_response_t**)` | Get transaction details |
| `int cellframe_rpc_get_block(const char*, uint64_t, cellframe_rpc_response_t**)` | Get block details |
| `int cellframe_rpc_get_balance(const char*, const char*, const char*, cellframe_rpc_response_t**)` | Get wallet balance |
| `int cellframe_rpc_get_utxo(const char*, const char*, const char*, cellframe_rpc_response_t**)` | Get UTXOs |
| `int cellframe_rpc_submit_tx(const char*, const char*, const char*, cellframe_rpc_response_t**)` | Submit transaction |
| `int cellframe_rpc_get_tx_history(const char*, const char*, cellframe_rpc_response_t**)` | Get transaction history |
| `void cellframe_rpc_response_free(cellframe_rpc_response_t*)` | Free RPC response |
| `int cellframe_verify_registration_tx(const char*, const char*, const char*)` | Verify DNA registration tx |

### 15.4 Cellframe Transaction Builder (`cellframe_tx_builder.h`)

| Function | Description |
|----------|-------------|
| `cellframe_tx_builder_t* cellframe_tx_builder_new(void)` | Create transaction builder |
| `void cellframe_tx_builder_free(cellframe_tx_builder_t*)` | Free transaction builder |
| `int cellframe_tx_set_timestamp(cellframe_tx_builder_t*, uint64_t)` | Set transaction timestamp |
| `int cellframe_tx_add_in(cellframe_tx_builder_t*, const cellframe_hash_t*, uint32_t)` | Add input |
| `int cellframe_tx_add_out(cellframe_tx_builder_t*, const cellframe_addr_t*, uint256_t)` | Add output (native) |
| `int cellframe_tx_add_out_ext(cellframe_tx_builder_t*, const cellframe_addr_t*, uint256_t, const char*)` | Add output (token) |
| `int cellframe_tx_add_fee(cellframe_tx_builder_t*, uint256_t)` | Add fee output |
| `int cellframe_tx_add_tsd(cellframe_tx_builder_t*, uint16_t, const uint8_t*, size_t)` | Add TSD data |
| `const uint8_t* cellframe_tx_get_signing_data(cellframe_tx_builder_t*, size_t*)` | Get data for signing |
| `const uint8_t* cellframe_tx_get_data(cellframe_tx_builder_t*, size_t*)` | Get complete tx data |
| `int cellframe_tx_add_signature(cellframe_tx_builder_t*, const uint8_t*, size_t)` | Add signature |
| `int cellframe_uint256_from_str(const char*, uint256_t*)` | Parse CELL to datoshi |
| `int cellframe_uint256_scan_uninteger(const char*, uint256_t*)` | Parse raw datoshi |
| `int cellframe_hex_to_bin(const char*, uint8_t*, size_t)` | Hex to binary |

---

## 16. Blockchain - Ethereum (`blockchain/ethereum/`)

Ethereum blockchain with secp256k1 ECDSA signatures.

### 16.1 Ethereum Wallet (`eth_wallet.h`)

| Function | Description |
|----------|-------------|
| `int eth_wallet_create_from_seed(const uint8_t*, size_t, const char*, const char*, char*)` | Create wallet from seed |
| `int eth_wallet_generate(const uint8_t*, size_t, eth_wallet_t*)` | Generate wallet in memory |
| `void eth_wallet_clear(eth_wallet_t*)` | Clear wallet securely |
| `int eth_wallet_save(const eth_wallet_t*, const char*, const char*)` | Save wallet to file |
| `int eth_wallet_load(const char*, eth_wallet_t*)` | Load wallet from file |
| `int eth_wallet_get_address(const char*, char*, size_t)` | Get address from file |
| `int eth_address_from_private_key(const uint8_t*, uint8_t*)` | Derive address from privkey |
| `int eth_address_to_hex(const uint8_t*, char*)` | Format checksummed hex |
| `bool eth_validate_address(const char*)` | Validate address format |
| `int eth_rpc_get_balance(const char*, char*, size_t)` | Get ETH balance |
| `int eth_rpc_set_endpoint(const char*)` | Set RPC endpoint |
| `const char* eth_rpc_get_endpoint(void)` | Get RPC endpoint |
| `int eth_rpc_get_transactions(const char*, eth_transaction_t**, int*)` | Get transaction history |
| `void eth_rpc_free_transactions(eth_transaction_t*, int)` | Free transactions |

### 16.2 Ethereum Transactions (`eth_tx.h`)

| Function | Description |
|----------|-------------|
| `int eth_tx_get_nonce(const char*, uint64_t*)` | Get transaction nonce |
| `int eth_tx_get_gas_price(uint64_t*)` | Get current gas price |
| `int eth_tx_estimate_gas(const char*, const char*, const char*, uint64_t*)` | Estimate gas |
| `void eth_tx_init_transfer(eth_tx_t*, uint64_t, uint64_t, const uint8_t*, const uint8_t*, uint64_t)` | Init transfer tx |
| `int eth_tx_sign(const eth_tx_t*, const uint8_t*, eth_signed_tx_t*)` | Sign transaction |
| `int eth_tx_send(const eth_signed_tx_t*, char*)` | Broadcast transaction |
| `int eth_send_eth(const uint8_t*, const char*, const char*, const char*, char*)` | Send ETH |
| `int eth_send_eth_with_gas(const uint8_t*, const char*, const char*, const char*, int, char*)` | Send with gas preset |
| `int eth_parse_amount(const char*, uint8_t*)` | Parse amount to wei |
| `int eth_parse_address(const char*, uint8_t*)` | Parse hex address |

---

## 17. Blockchain - Solana (`blockchain/solana/`)

Solana blockchain with Ed25519 signatures.

### 17.1 Solana Wallet (`sol_wallet.h`)

| Function | Description |
|----------|-------------|
| `int sol_wallet_generate(const uint8_t*, size_t, sol_wallet_t*)` | Generate wallet from seed |
| `int sol_wallet_create_from_seed(const uint8_t*, size_t, const char*, const char*, char*)` | Create and save wallet |
| `int sol_wallet_load(const char*, sol_wallet_t*)` | Load wallet from file |
| `int sol_wallet_save(const sol_wallet_t*, const char*, const char*)` | Save wallet to file |
| `void sol_wallet_clear(sol_wallet_t*)` | Clear wallet from memory |
| `int sol_pubkey_to_address(const uint8_t*, char*)` | Public key to base58 |
| `int sol_address_to_pubkey(const char*, uint8_t*)` | Base58 to public key |
| `bool sol_validate_address(const char*)` | Validate address format |
| `int sol_sign_message(const uint8_t*, size_t, const uint8_t*, const uint8_t*, uint8_t*)` | Sign message |
| `void sol_rpc_set_endpoint(const char*)` | Set RPC endpoint |
| `const char* sol_rpc_get_endpoint(void)` | Get RPC endpoint |

### 17.2 Solana Transactions (`sol_tx.h`)

| Function | Description |
|----------|-------------|
| `int sol_tx_build_transfer(const sol_wallet_t*, const uint8_t*, uint64_t, const uint8_t*, uint8_t*, size_t, size_t*)` | Build transfer tx |
| `int sol_tx_send_lamports(const sol_wallet_t*, const char*, uint64_t, char*, size_t)` | Send in lamports |
| `int sol_tx_send_sol(const sol_wallet_t*, const char*, double, char*, size_t)` | Send in SOL |

---

## 18. Blockchain - TRON (`blockchain/tron/`)

TRON blockchain with secp256k1 signatures.

### 18.1 TRON Wallet (`trx_wallet.h`)

| Function | Description |
|----------|-------------|
| `int trx_wallet_generate(const uint8_t*, size_t, trx_wallet_t*)` | Generate wallet from seed |
| `int trx_wallet_create_from_seed(const uint8_t*, size_t, const char*, const char*, char*)` | Create and save wallet |
| `void trx_wallet_clear(trx_wallet_t*)` | Clear wallet securely |
| `int trx_wallet_save(const trx_wallet_t*, const char*, const char*)` | Save wallet to file |
| `int trx_wallet_load(const char*, trx_wallet_t*)` | Load wallet from file |
| `int trx_wallet_get_address(const char*, char*, size_t)` | Get address from file |
| `int trx_address_from_pubkey(const uint8_t*, uint8_t*)` | Derive address from pubkey |
| `int trx_address_to_base58(const uint8_t*, char*, size_t)` | Encode address as base58 |
| `int trx_address_from_base58(const char*, uint8_t*)` | Decode base58 address |
| `bool trx_validate_address(const char*)` | Validate address format |
| `int trx_rpc_set_endpoint(const char*)` | Set RPC endpoint |
| `const char* trx_rpc_get_endpoint(void)` | Get RPC endpoint |

### 18.2 TRON Transactions (`trx_tx.h`)

| Function | Description |
|----------|-------------|
| `int trx_tx_create_transfer(const char*, const char*, uint64_t, trx_tx_t*)` | Create TRX transfer |
| `int trx_tx_create_trc20_transfer(const char*, const char*, const char*, const char*, trx_tx_t*)` | Create TRC-20 transfer |
| `int trx_tx_sign(const trx_tx_t*, const uint8_t*, trx_signed_tx_t*)` | Sign transaction |
| `int trx_tx_broadcast(const trx_signed_tx_t*, char*)` | Broadcast transaction |
| `int trx_send_trx(const uint8_t*, const char*, const char*, const char*, char*)` | Send TRX |
| `int trx_parse_amount(const char*, uint64_t*)` | Parse TRX to SUN |
| `int trx_hex_to_base58(const char*, char*, size_t)` | Hex to base58 |
| `int trx_base58_to_hex(const char*, char*, size_t)` | Base58 to hex |
