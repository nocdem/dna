# Cellframe Platform - Comprehensive Guide

This document provides a comprehensive overview of the Cellframe platform, combining our exploration of the `cellframe-node-cli` tool and available information from the Cellframe wiki.

## Table of Contents

1. [Introduction](#introduction)
2. [Cellframe Architecture](#cellframe-architecture)
3. [Networks and Chains](#networks-and-chains)
4. [Node Management](#node-management)
5. [Wallet Operations](#wallet-operations)
6. [Transaction Management](#transaction-management)
7. [Blockchain Operations](#blockchain-operations)
8. [Decentralized Exchange (DEX)](#decentralized-exchange-dex)
9. [Token Management](#token-management)
10. [Staking and Delegation](#staking-and-delegation)
11. [Global Database](#global-database)
12. [Services](#services)
13. [Command Reference](#command-reference)
14. [Troubleshooting](#troubleshooting)

## Introduction

Cellframe is a quantum-resistant blockchain platform designed to support various network topologies and consensus mechanisms. The platform operates with multiple networks simultaneously (like Backbone and KelVPN), providing a secure and flexible infrastructure for decentralized applications.

### Key Features

- Quantum-resistant cryptography
- Multi-chain architecture
- Directed Acyclic Graph (DAG) structure
- Decentralized Exchange (DEX)
- Token management including custom token creation
- Staking and delegation mechanisms
- VPN services (KelVPN)
- Global database for distributed data storage

### Primary Components

- **cellframe-node**: Main node daemon
- **cellframe-node-cli**: Command-line interface for interacting with the node
- **cellframe-node-tool**: Utility for certificate and wallet management
- **cellframe-node-config**: Configuration utility
- **cellframe-diagtool**: Diagnostic tool

## Cellframe Architecture

The Cellframe architecture is based on a multi-chain, multi-network design:

### Networks

- **Backbone**: The primary Cellframe network, handling core blockchain functions
- **KelVPN**: Network focused on providing VPN services
- Each network can have its own set of chains, configurations, and consensus mechanisms

### Chains

Each network can contain multiple chains with different purposes:
- **zerochain**: Initial chain containing the genesis block
- **main**: Main chain for regular transactions
- Other chains can be defined for specific applications or purposes

### Cryptography

Cellframe employs post-quantum cryptographic algorithms including:
- **DILITHIUM**: Signature scheme
- **FALCON**: Fast Fourier lattice-based compact signatures
- **SPHINCS**: Stateless hash-based signatures
- **Multi-chained signatures**: Combining multiple signature types

### Directed Acyclic Graph (DAG)

Cellframe uses a DAG structure for certain aspects of its blockchain:
- Events are organized in a directed graph without cycles
- Allows for parallel processing of transactions
- Provides higher throughput compared to traditional blockchain designs

## Networks and Chains

### Network Management

The Cellframe node can operate on multiple networks simultaneously. Common operations include:

**List Networks:**
```
/opt/cellframe-node/bin/cellframe-node-cli net list
```

**Network Status:**
```
/opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> get status
```

**List Chains in Network:**
```
/opt/cellframe-node/bin/cellframe-node-cli net list chains -net <network_name>
```

**Network Synchronization:**
```
/opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> sync chains
```

### Synchronization Modes

- **update**: Default mode, only updates new chains and global database
- **all**: Updates everything from zero

### Network Configuration

Network configurations are stored in:
- `/opt/cellframe-node/etc/network/`

Each network has its own configuration files:
- `Backbone.cfg`
- `KelVPN.cfg`

Chain configurations are stored in subdirectories:
- `/opt/cellframe-node/etc/network/Backbone/chain-0.cfg`
- `/opt/cellframe-node/etc/network/Backbone/main.cfg`

## Node Management

### Node Commands

**List Nodes:**
```
/opt/cellframe-node/bin/cellframe-node-cli node list -net <net_name> [-addr <node_address> | -alias <node_alias>] [-full]
```

**Add/Delete Nodes:**
```
/opt/cellframe-node/bin/cellframe-node-cli node add -net <net_name> [-port <port>]
/opt/cellframe-node/bin/cellframe-node-cli node del -net <net_name> {-addr <node_address> | -alias <node_alias>}
```

**Node Handshake:**
```
/opt/cellframe-node/bin/cellframe-node-cli node handshake -net <network_name> -addr <node_address>
```

**List Node Connections:**
```
/opt/cellframe-node/bin/cellframe-node-cli node connections
```

### Node Configuration

The main node configuration is stored in:
- `/opt/cellframe-node/etc/cellframe-node.cfg`

This configuration file contains settings for:
- Server configuration (ports, addresses)
- Network parameters
- Logging settings
- Resource limits

## Wallet Operations

Cellframe wallets manage cryptographic keys and provide an interface for transaction management.

### Wallet Commands

**Create Wallet:**
```
/opt/cellframe-node/bin/cellframe-node-cli wallet new -w <wallet_name> -sign <signature_type> [-password <password>]
```

**Activate Wallet:**
```
/opt/cellframe-node/bin/cellframe-node-cli wallet activate -w <wallet_name> -password <password> [-ttl <minutes>]
```

**Deactivate Wallet:**
```
/opt/cellframe-node/bin/cellframe-node-cli wallet deactivate -w <wallet_name>
```

**List Wallets:**
```
/opt/cellframe-node/bin/cellframe-node-cli wallet list
```

**Wallet Information:**
```
/opt/cellframe-node/bin/cellframe-node-cli wallet info -w <wallet_name> -net <network_name>
```

### Signature Types

- `sig_dil`: DILITHIUM (quantum-resistant)
- `sig_falcon`: FALCON (quantum-resistant)
- `sig_sphincs`: SPHINCS (quantum-resistant)
- `sig_multi_chained`: Multiple chained signatures

### Wallet Storage

Wallets are stored in:
- `/opt/cellframe-node/var/lib/wallet/`

## Transaction Management

Transactions in Cellframe represent transfers of value or other operations on the blockchain.

### Transaction Commands

**Create Transaction:**
```
/opt/cellframe-node/bin/cellframe-node-cli tx_create -net <net_name> [-chain <chain_name>] -value <value> -token <token_ticker> -to_addr <addr> {-from_wallet <wallet_name> | -from_emission <emission_hash> {-cert <cert_name> | -wallet_fee <wallet_name>}} -fee <value>
```

**Verify Transaction:**
```
/opt/cellframe-node/bin/cellframe-node-cli tx_verify -net <net_name> [-chain <chain_name>] -tx <tx_hash>
```

**Transaction History:**
```
/opt/cellframe-node/bin/cellframe-node-cli tx_history {-addr <addr> | {-w <wallet_name> | -tx <tx_hash>} -net <net_name>} [-chain <chain_name>] [-limit] [-offset] [-head]
```

### Conditional Transactions

For services that require conditional execution:

```
/opt/cellframe-node/bin/cellframe-node-cli tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name> -cert <pub_cert_name> -value <value_datoshi> -fee <value> -unit {B | SEC} -srv_uid <numeric_uid>
```

## Blockchain Operations

Cellframe supports both traditional blockchain and DAG structures.

### DAG Operations

**List Events:**
```
/opt/cellframe-node/bin/cellframe-node-cli dag event list -net <net_name> [-chain <chain_name>] -from {events | events_lasts | threshold | round.new | round.<Round_id_in_hex>} [-limit] [-offset] [-head] [-from_hash <event_hash>] [-to_hash <event_hash>] [-from_date <YYMMDD>] [-to_date <YYMMDD>]
```

**Count Events:**
```
/opt/cellframe-node/bin/cellframe-node-cli dag event count -net <net_name> [-chain <chain_name>]
```

### Block Operations

**List Blocks:**
```
/opt/cellframe-node/bin/cellframe-node-cli block -net <net_name> [-chain <chain_name>] list [{signed | first_signed}] [-limit] [-offset] [-head] [-from_hash <block_hash>] [-to_hash <block_hash>] [-from_date <YYMMDD>] [-to_date <YYMMDD>] [{-cert <signing_cert_name> | -pkey_hash <signing_cert_pkey_hash>}] [-unspent]
```

**Dump Block Info:**
```
/opt/cellframe-node/bin/cellframe-node-cli block -net <net_name> [-chain <chain_name>] [-brief] dump {-hash <block_hash> | -num <block_number>}
```

### Mempool Operations

**List Mempool Entries:**
```
/opt/cellframe-node/bin/cellframe-node-cli mempool list -net <net_name> [-chain <chain_name>] [-addr <addr>] [-brief] [-limit] [-offset]
```

**Process Mempool Entry:**
```
/opt/cellframe-node/bin/cellframe-node-cli mempool proc -net <net_name> [-chain <chain_name>] -datum <datum_hash>
```

## Decentralized Exchange (DEX)

Cellframe includes a built-in decentralized exchange (DEX) for trading tokens.

### Service Management

**Enable/Disable Exchange Service:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange enable
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange disable
```

### Order Management

**List Orders:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange orders -net <net_name> [-status {opened|closed|all}] [-token_from <token_ticker>] [-token_to <token_ticker>] [-addr <wallet_addr>] [-limit <limit>] [-offset <offset>] [-head]
```

**Create Order:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange order create -net <net_name> -token_sell <token_ticker> -token_buy <token_ticker> -w <wallet_name> -value <value> -rate <value> -fee <value>
```

**Remove Order:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange order remove -net <net_name> -order <order_hash> -w <wallet_name> -fee <value_datoshi>
```

### Token Pair Operations

**List Token Pairs:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange token_pair -net <net_name> list all [-limit <limit>] [-offset <offset>]
```

**Get Average Rate:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange token_pair -net <net_name> rate average -token_from <token_ticker> -token_to <token_ticker> [-time_from <From_time>] [-time_to <To_time>]
```

### Transaction Management

**Purchase Using Order:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange purchase -order <order hash> -net <net_name> -w <wallet_name> -value <value> -fee <value>
```

**List Transactions:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange tx_list -net <net_name> [-time_from <From_time>] [-time_to <To_time>][-addr <wallet_addr>]  [-status {inactive|active|all}]
```

## Token Management

Cellframe supports custom token creation and management.

### Token Declaration

**Declare Simple Token:**
```
/opt/cellframe-node/bin/cellframe-node-cli token_decl -net <net_name> [-chain <chain_name>] -token <token_ticker> -total_supply <total_supply> -signs_total <sign_total> -signs_emission <signs_for_emission> -certs <certs_list>
```

**Declare CF20 Token:**
```
/opt/cellframe-node/bin/cellframe-node-cli token_decl -net <net_name> [-chain <chain_name>] -token <token_ticker> -type CF20 -total_supply <total_supply/if_0 =_endless> -decimals <18> -signs_total <sign_total> -signs_emission <signs_for_emission> -certs <certs_list> -flags [<Flag_1>][,<Flag_2>]...[,<Flag_N>]... [-<Param_name_1> <Param_Value_1>] [-Param_name_2> <Param_Value_2>] ...[-<Param_Name_N> <Param_Value_N>]
```

### Token Emission

**Create Emission:**
```
/opt/cellframe-node/bin/cellframe-node-cli token_emit -token <mempool_token_ticker> -emission_value <value> -addr <addr> -chain_emission <chain_name> -net <net_name> -certs <cert_list>
```

**Sign Emission:**
```
/opt/cellframe-node/bin/cellframe-node-cli token_emit sign -emission <hash> -net <net_name> -certs <cert_list>
```

### Token Information

**Get Token Info:**
```
/opt/cellframe-node/bin/cellframe-node-cli token info -net <net_name> -name <token_ticker>
```

**List Coins:**
```
/opt/cellframe-node/bin/cellframe-node-cli ledger list coins -net <net_name> [-limit] [-offset]
```

## Staking and Delegation

Cellframe supports staking and delegation for consensus and token rewards.

### Stake Service

**Create Orders:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake order create [fee] -net <net_name> -value <value> -cert <priv_cert_name> [-H {hex(default) | base58}]
```

**Create Validator Order:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake order create validator -net <net_name> -value_min <minimum_stake_value> -value_max <maximum_stake_value> -tax <percent> -cert <priv_cert_name> [-node_addr <for_validator_node>] [-H {hex(default) | base58}]
```

**Create Staker Order:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake order create staker -net <net_name> -w <wallet_with_m_tokens> -value <stake_value> -fee <value> -tax <percent> [-addr <for_tax_collecting>]  [-cert <for_order_signing>] [-H {hex(default) | base58}]
```

### Stake Delegation

**Delegate Stake:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake delegate {[-cert <pub_cert_name> | {-pkey <pkey_hash> | -pkey_full <pkey>}-sign_type <sign_type>] -value <datoshi> | -order <order_hash> {[-tax_addr <wallet_addr_for_tax_collecting>] | -cert <priv_cert_name> [-node_addr <for_validator_node>]}} -net <net_name> -w <wallet_name> -fee <value>
```

**Update Stake:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake update -net <net_name> {-tx <transaction_hash> | -cert <delegated_cert>} -w <wallet_name> -value <new_delegation_value> -fee <value>
```

### Rewards

**Get Validator Rewards:**
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake reward -net <net_name> {-node_addr <node_address>} [-date_from <YYMMDD> -date_to <YYMMDD>] [-brief] [-limit] [-offset] [-head]
```

## Global Database

Cellframe includes a distributed global database for key-value storage.

### Operations

**Flush to Disk:**
```
/opt/cellframe-node/bin/cellframe-node-cli global_db flush
```

**Write Key-Value:**
```
/opt/cellframe-node/bin/cellframe-node-cli global_db write -group <group_name> -key <key_name> -value <value>
```

**Read Key-Value:**
```
/opt/cellframe-node/bin/cellframe-node-cli global_db read -group <group_name> -key <key_name>
```

**Delete Key-Value:**
```
/opt/cellframe-node/bin/cellframe-node-cli global_db delete -group <group_name> -key <key_name>
```

### Group Management

**List Groups:**
```
/opt/cellframe-node/bin/cellframe-node-cli global_db group_list
```

**Drop Table:**
```
/opt/cellframe-node/bin/cellframe-node-cli global_db drop_table -group <group_name>
```

**Get Keys in Group:**
```
/opt/cellframe-node/bin/cellframe-node-cli global_db get_keys -group <group_name>
```

## Services

Cellframe supports various services built on its infrastructure.

### VPN Client

**Initialize VPN Client:**
```
/opt/cellframe-node/bin/cellframe-node-cli vpn_client init -w <wallet_name> -token <token_name> -value <value> -net <net_name>
```

**Control VPN Client:**
```
/opt/cellframe-node/bin/cellframe-node-cli vpn_client [start -addr <server_address> -port <server_port>|stop|status] -net <net_name>
```

**Check VPN Service:**
```
/opt/cellframe-node/bin/cellframe-node-cli vpn_client check -addr <ip_addr> -port <port> -net <net_name>
```

### Emission Delegation Service

**Create Delegation:**
```
/opt/cellframe-node/bin/cellframe-node-cli emit_delegate hold -net <net_name> -w <wallet_name> -token <ticker> -value <value> -fee <value> -signs_minimum <value_int> -pkey_hashes <hash1[,hash2,...,hashN]> [-tag "<str>"] [-H {hex(default) | base58}]
```

**Refill Delegation:**
```
/opt/cellframe-node/bin/cellframe-node-cli emit_delegate refill -net <net_name> -w <wallet_name> -value <value> -fee <value> -tx <transaction_hash> [-H {hex(default) | base58}]
```

### Voting and Polls

**Create Poll:**
```
/opt/cellframe-node/bin/cellframe-node-cli poll create -net <net_name> -question <"Question_string"> -options <"Option0", "Option1" ... "OptionN"> [-expire <poll_expire_time_in_RCF822>] [-max_votes_count <Votes_count>] [-delegated_key_required] [-vote_changing_allowed] -fee <value_datoshi> -w <fee_wallet_name> [-token <ticker>]
```

**Vote in Poll:**
```
/opt/cellframe-node/bin/cellframe-node-cli poll vote -net <net_name> -hash <poll_hash> -option_idx <option_index> [-cert <delegate_cert_name>] -fee <value_datoshi> -w <fee_wallet_name>
```

## Command Reference

Most commands in the `cellframe-node-cli` follow a similar pattern:

```
/opt/cellframe-node/bin/cellframe-node-cli [command] [subcommand] [parameters]
```

Parameters are typically specified with a dash prefix:
```
-net <network_name> -chain <chain_name> -parameter <value>
```

Get help for any command:
```
/opt/cellframe-node/bin/cellframe-node-cli help [command]
```

## Troubleshooting

### Log Management

**Print Log:**
```
/opt/cellframe-node/bin/cellframe-node-cli print_log -l_ts_after <timestamp>
```

### Diagnostic Tool

**Run Diagnostic Tool:**
```
/opt/cellframe-node/bin/cellframe-diagtool -cfg
```

### Chain Synchronization Issues

When facing synchronization issues:

1. Check network status:
   ```
   /opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> get status
   ```

2. Force resynchronization:
   ```
   /opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> -mode all sync all
   ```

3. Specifically sync global database:
   ```
   /opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> sync -mode all gdb
   ```

### Common Error Codes

- `Code 1`: Missing required parameter
- `Code 2`: Invalid command or parameter
- `Code 3`: Not found (e.g., "Couldn't find any wallets")
- `Code 9`: Insufficient funds
- `Code 14`: Invalid signature type
- `Code 28`: Database ACL group not defined
- `Code 34`: Missing subcommand
- `Code 57`: "Can't find orders for specified token pair"
- `Code 58`: "Can't find transactions"
- `Code 102`: Missing required parameter for DAG commands

---

This guide was created based on exploration of the `cellframe-node-cli` tool and information from the Cellframe documentation. For the most up-to-date information, refer to the official Cellframe wiki at https://wiki.cellframe.net.