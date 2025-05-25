# Cellframe Node CLI Reference Guide

This document provides a comprehensive overview of the Cellframe Node CLI commands, functionality, and usage patterns based on exploration of the `cellframe-node-cli` tool.

## Table of Contents
1. [Introduction](#introduction)
2. [Installation and Setup](#installation-and-setup)
3. [Common Command Patterns](#common-command-patterns)
4. [Network Management](#network-management)
5. [Wallet Operations](#wallet-operations)
6. [Transaction Management](#transaction-management)
7. [Blockchain Operations](#blockchain-operations)
8. [Decentralized Exchange](#decentralized-exchange)
9. [Node Management](#node-management)
10. [Global Database](#global-database)
11. [Staking and Delegation](#staking-and-delegation)
12. [Services](#services)
13. [Troubleshooting](#troubleshooting)

## Introduction

The Cellframe Node CLI (`cellframe-node-cli`) is a command-line interface for interacting with the Cellframe blockchain node. It allows users to perform a wide range of operations including managing wallets, executing transactions, interacting with the DEX (Decentralized Exchange), staking, network management, and more.

Cellframe is a quantum-resistant blockchain platform designed to support various network topologies and consensus mechanisms. The node software operates with multiple networks simultaneously (like Backbone and KelVPN).

### Primary Components

- **cellframe-node**: Main node daemon
- **cellframe-node-cli**: Command-line interface for interacting with the node
- **cellframe-node-tool**: Utility for certificate and wallet management
- **cellframe-node-config**: Configuration utility
- **cellframe-diagtool**: Diagnostic tool

## Installation and Setup

The Cellframe node is typically installed in the following path:

```
/opt/cellframe-node/
```

Key directories:
- `/opt/cellframe-node/bin/`: Executable binaries
- `/opt/cellframe-node/etc/`: Configuration files
- `/opt/cellframe-node/var/lib/`: Data storage (wallets, global database, etc.)
- `/opt/cellframe-node/var/log/`: Log files

## Common Command Patterns

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

## Network Management

The Cellframe node can operate on multiple networks simultaneously. Main networks include Backbone and KelVPN.

### List Networks

```
/opt/cellframe-node/bin/cellframe-node-cli net list
```

### Network Status

```
/opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> get status
```

Example output:
```
status: 
    net: Backbone
    current_addr: 2C89::715C::7832::2E92
    links: 
        active: 3
        required: 3
    processed: 
        zerochain: 
            status: sync in process
            current: 72390
            in network: 104187
            percent: 69.481 %
        main: 
            status: idle
            current: 0
            in network: 0
            percent:  - %
    states: 
        current: NET_STATE_SYNC_CHAINS
        target: NET_STATE_SYNC_CHAINS
```

### List Chains in Network

```
/opt/cellframe-node/bin/cellframe-node-cli net list chains -net <network_name>
```

Example: 
```
net: Backbone
chains: 
    zerochain, 
    main
```

### Network Fee Information

```
/opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> get fee
```

### Network Synchronization

Start network synchronization:
```
/opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> sync chains
```

Synchronize global database:
```
/opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> sync -mode all gdb
```

Synchronization modes can be:
- `update`: Default mode, only updates new chains and gdb
- `all`: Updates everything from zero

### Node Handshake

Establish connection with a specific node:
```
/opt/cellframe-node/bin/cellframe-node-cli node handshake -net <network_name> -addr <node_address>
```

### List Node Connections

```
/opt/cellframe-node/bin/cellframe-node-cli node connections
```

### List Authority Certificates

```
/opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> poa_certs list
```

## Wallet Operations

### Create Wallet

```
/opt/cellframe-node/bin/cellframe-node-cli wallet new -w <wallet_name> -sign <signature_type> [-password <password>]
```

Signature types:
- `sig_dil`: DILITHIUM
- `sig_falcon`: FALCON
- `sig_sphincs`: SPHINCS
- `sig_multi_chained`: Multiple chained signatures

### Activate Wallet

```
/opt/cellframe-node/bin/cellframe-node-cli wallet activate -w <wallet_name> -password <password> [-ttl <minutes>]
```

### Deactivate Wallet

```
/opt/cellframe-node/bin/cellframe-node-cli wallet deactivate -w <wallet_name>
```

### List Wallets

```
/opt/cellframe-node/bin/cellframe-node-cli wallet list
```

### Wallet Information

```
/opt/cellframe-node/bin/cellframe-node-cli wallet info -w <wallet_name> -net <network_name>
```

### Wallet Outputs

```
/opt/cellframe-node/bin/cellframe-node-cli wallet outputs {-addr <addr> | -w <wallet_name>} -net <network_name> -token <token_ticker> [{-cond | -value <uint256_value>}]
```

## Transaction Management

### Create Transaction

```
/opt/cellframe-node/bin/cellframe-node-cli tx_create -net <net_name> [-chain <chain_name>] -value <value> -token <token_ticker> -to_addr <addr> {-from_wallet <wallet_name> | -from_emission <emission_hash> {-cert <cert_name> | -wallet_fee <wallet_name>}} -fee <value>
```

### Create Transaction from JSON

```
/opt/cellframe-node/bin/cellframe-node-cli tx_create_json -net <net_name> -json <json_data>
```

### Create Conditional Transaction

For services that require conditional transactions:

```
/opt/cellframe-node/bin/cellframe-node-cli tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name> -cert <pub_cert_name> -value <value_datoshi> -fee <value> -unit {B | SEC} -srv_uid <numeric_uid>
```

### Verify Transaction

```
/opt/cellframe-node/bin/cellframe-node-cli tx_verify -net <net_name> [-chain <chain_name>] -tx <tx_hash>
```

### Transaction History

```
/opt/cellframe-node/bin/cellframe-node-cli tx_history {-addr <addr> | {-w <wallet_name> | -tx <tx_hash>} -net <net_name>} [-chain <chain_name>] [-limit] [-offset] [-head]
```

For all transactions:
```
/opt/cellframe-node/bin/cellframe-node-cli tx_history -all -net <net_name> [-chain <chain_name>] [-limit] [-offset] [-head]
```

For transaction count:
```
/opt/cellframe-node/bin/cellframe-node-cli tx_history -count -net <net_name>
```

## Blockchain Operations

### DAG Operations (Directed Acyclic Graph)

List events:
```
/opt/cellframe-node/bin/cellframe-node-cli dag event list -net <net_name> [-chain <chain_name>] -from {events | events_lasts | threshold | round.new | round.<Round_id_in_hex>} [-limit] [-offset] [-head] [-from_hash <event_hash>] [-to_hash <event_hash>] [-from_date <YYMMDD>] [-to_date <YYMMDD>]
```

Count events:
```
/opt/cellframe-node/bin/cellframe-node-cli dag event count -net <net_name> [-chain <chain_name>]
```

Dump event info:
```
/opt/cellframe-node/bin/cellframe-node-cli dag event dump -net <net_name> [-chain <chain_name>] -event <event_hash> -from {events | events_lasts | threshold | round.new  | round.<Round_id_in_hex>} [-H {hex | base58(default)}]
```

### Block Operations

List blocks:
```
/opt/cellframe-node/bin/cellframe-node-cli block -net <net_name> [-chain <chain_name>] list [{signed | first_signed}] [-limit] [-offset] [-head] [-from_hash <block_hash>] [-to_hash <block_hash>] [-from_date <YYMMDD>] [-to_date <YYMMDD>] [{-cert <signing_cert_name> | -pkey_hash <signing_cert_pkey_hash>}] [-unspent]
```

Dump block info:
```
/opt/cellframe-node/bin/cellframe-node-cli block -net <net_name> [-chain <chain_name>] [-brief] dump {-hash <block_hash> | -num <block_number>}
```

### Search and Find Commands

Find datum:
```
/opt/cellframe-node/bin/cellframe-node-cli find datum -net <net_name> [-chain <chain_name>] -hash <datum_hash>
```

Find atom:
```
/opt/cellframe-node/bin/cellframe-node-cli find atom -net <net_name> [-chain <chain_name>] -hash <atom_hash>
```

Find decree:
```
/opt/cellframe-node/bin/cellframe-node-cli find decree -net <net_name> [-chain <chain_name>] -type <type_decree> [-where <chains|mempool>]
```

## Decentralized Exchange

### Service Management

Enable exchange service:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange enable
```

Disable exchange service:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange disable
```

### Order Management

List orders:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange orders -net <net_name> [-status {opened|closed|all}] [-token_from <token_ticker>] [-token_to <token_ticker>] [-addr <wallet_addr>] [-limit <limit>] [-offset <offset>] [-head]
```

Create order:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange order create -net <net_name> -token_sell <token_ticker> -token_buy <token_ticker> -w <wallet_name> -value <value> -rate <value> -fee <value>
```

Remove order:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange order remove -net <net_name> -order <order_hash> -w <wallet_name> -fee <value_datoshi>
```

### Order History and Status

Order history:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange order history -net <net_name> {-order <order_hash> | -addr <wallet_addr>}
```

Order status:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange order status -net <net_name> -order <order_hash>
```

### Token Pair Operations

List token pairs:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange token_pair -net <net_name> list all [-limit <limit>] [-offset <offset>]
```

Get average rate:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange token_pair -net <net_name> rate average -token_from <token_ticker> -token_to <token_ticker> [-time_from <From_time>] [-time_to <To_time>]
```

Get rate history:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange token_pair -net <net_name> rate history -token_from <token_ticker> -token_to <token_ticker> [-time_from <From_time>] [-time_to <To_time>] [-limit <limit>] [-offset <offset>]
```

### Transaction Management

Purchase using order:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange purchase -order <order hash> -net <net_name> -w <wallet_name> -value <value> -fee <value>
```

List transactions:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_xchange tx_list -net <net_name> [-time_from <From_time>] [-time_to <To_time>][-addr <wallet_addr>]  [-status {inactive|active|all}]
```

## Node Management

### List Nodes

```
/opt/cellframe-node/bin/cellframe-node-cli node list -net <net_name> [-addr <node_address> | -alias <node_alias>] [-full]
```

### Add/Delete Nodes

Add node:
```
/opt/cellframe-node/bin/cellframe-node-cli node add -net <net_name> [-port <port>]
```

Delete node:
```
/opt/cellframe-node/bin/cellframe-node-cli node del -net <net_name> {-addr <node_address> | -alias <node_alias>}
```

### Node Connection Management

Add/delete link:
```
/opt/cellframe-node/bin/cellframe-node-cli node link {add | del} -net <net_name> {-addr <node_address> | -alias <node_alias>} -link <node_address>
```

Connect to node:
```
/opt/cellframe-node/bin/cellframe-node-cli node connect -net <net_name> {-addr <node_address> | -alias <node_alias> | auto}
```

### Node Aliases

```
/opt/cellframe-node/bin/cellframe-node-cli node alias -addr <node_address> -alias <node_alias>
```

### Node Ban Management

Ban node:
```
/opt/cellframe-node/bin/cellframe-node-cli node ban -net <net_name> -certs <certs_name> [-addr <node_address> | -host <ip_v4_or_v6_address>]
```

Unban node:
```
/opt/cellframe-node/bin/cellframe-node-cli node unban -net <net_name> -certs <certs_name> [-addr <node_address> | -host <ip_v4_or_v6_address>]
```

View ban list:
```
/opt/cellframe-node/bin/cellframe-node-cli node banlist
```

### Node Balancer

```
/opt/cellframe-node/bin/cellframe-node-cli node balancer -net <net_name>
```

## Global Database

### Operations

Flush to disk:
```
/opt/cellframe-node/bin/cellframe-node-cli global_db flush
```

Write key-value:
```
/opt/cellframe-node/bin/cellframe-node-cli global_db write -group <group_name> -key <key_name> -value <value>
```

Read key-value:
```
/opt/cellframe-node/bin/cellframe-node-cli global_db read -group <group_name> -key <key_name>
```

Delete key-value:
```
/opt/cellframe-node/bin/cellframe-node-cli global_db delete -group <group_name> -key <key_name>
```

### Group Management

List groups:
```
/opt/cellframe-node/bin/cellframe-node-cli global_db group_list
```

Drop table:
```
/opt/cellframe-node/bin/cellframe-node-cli global_db drop_table -group <group_name>
```

Get keys in group:
```
/opt/cellframe-node/bin/cellframe-node-cli global_db get_keys -group <group_name>
```

### Export/Import

Export to JSON:
```
/opt/cellframe-node/bin/cellframe-node-cli gdb_export filename <filename without extension> [-groups <group names list>]
```

Import from JSON:
```
/opt/cellframe-node/bin/cellframe-node-cli gdb_import filename <filename without extension>
```

## Staking and Delegation

### Delegated Stake Service

Create orders:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake order create [fee] -net <net_name> -value <value> -cert <priv_cert_name> [-H {hex(default) | base58}]
```

Create validator order:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake order create validator -net <net_name> -value_min <minimum_stake_value> -value_max <maximum_stake_value> -tax <percent> -cert <priv_cert_name> [-node_addr <for_validator_node>] [-H {hex(default) | base58}]
```

Create staker order:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake order create staker -net <net_name> -w <wallet_with_m_tokens> -value <stake_value> -fee <value> -tax <percent> [-addr <for_tax_collecting>]  [-cert <for_order_signing>] [-H {hex(default) | base58}]
```

List orders:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake order list [fee | validator | staker] -net <net_name>
```

Remove order:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake order remove -net <net_name> -order <order_hash>
```

### Stake Delegation

Delegate stake:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake delegate {[-cert <pub_cert_name> | {-pkey <pkey_hash> | -pkey_full <pkey>}-sign_type <sign_type>] -value <datoshi> | -order <order_hash> {[-tax_addr <wallet_addr_for_tax_collecting>] | -cert <priv_cert_name> [-node_addr <for_validator_node>]}} -net <net_name> -w <wallet_name> -fee <value>
```

Update stake:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake update -net <net_name> {-tx <transaction_hash> | -cert <delegated_cert>} -w <wallet_name> -value <new_delegation_value> -fee <value>
```

Invalidate stake:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake invalidate -net <net_name> {-tx <transaction_hash> -w <wallet_name> -fee <value> | -siging_pkey_hash <pkey_hash> -signing_pkey_type <pkey_type> -poa_cert <cert_name>}
```

Approve stake:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake approve -net <net_name> -tx <transaction_hash> -poa_cert <priv_cert_name>
```

### Stake Key Management

List active stake keys:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake list keys -net <net_name> [-cert <delegated_cert> | -pkey <pkey_hash_str>]
```

List key delegation transactions:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake list tx -net <net_name> 
```

Set minimum stake value:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake min_value -net <net_name> [-chain <chain_name>] -poa_cert <poa_cert_name> -value <value>
```

Set maximum validator weight:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake max_weight -net <net_name> [-chain <chain_name>] -poa_cert <poa_cert_name> -percent <value>
```

Check remote validator:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake check -net <net_name> -tx <tx_hash>
```

Get rewards for validators:
```
/opt/cellframe-node/bin/cellframe-node-cli srv_stake reward -net <net_name> {-node_addr <node_address>} [-date_from <YYMMDD> -date_to <YYMMDD>] [-brief] [-limit] [-offset] [-head]
```

### Stake Lock Service

Hold stake:
```
/opt/cellframe-node/bin/cellframe-node-cli stake_lock hold -net <net_name> -w <wallet_name> -time_staking <YYMMDD> -token <ticker> -value <value> -fee <value>[-chain <chain_name>] [-reinvest <percentage>]
```

Take stake:
```
/opt/cellframe-node/bin/cellframe-node-cli stake_lock take -net <net_name> -w <wallet_name> -tx <transaction_hash> -fee <value>[-chain <chain_name>]
```

## Services

### Network Service Management

Find orders:
```
/opt/cellframe-node/bin/cellframe-node-cli net_srv -net <net_name> order find [-direction {sell|buy}] [-srv_uid <service_UID>] [-price_unit <price_unit>] [-price_token <token_ticker>] [-price_min <price_minimum>] [-price_max <price_maximum>]
```

Delete order:
```
/opt/cellframe-node/bin/cellframe-node-cli net_srv -net <net_name> order delete -hash <order_hash>
```

Create order:
```
/opt/cellframe-node/bin/cellframe-node-cli net_srv -net <net_name> order create -direction {sell|buy} -srv_uid <service_UID> -price <price> -price_unit <price_unit> -price_token <token_ticker> -units <units> [-node_addr <node_address>] [-tx_cond <TX_cond_hash>] [-expires <unix_time_when_expires>] [-cert <cert_name_to_sign_order>] [{-ext <extension_with_params>|-region <region_name> -continent <continent_name>}]
```

### VPN Client

Initialize VPN client:
```
/opt/cellframe-node/bin/cellframe-node-cli vpn_client init -w <wallet_name> -token <token_name> -value <value> -net <net_name>
```

Control VPN client:
```
/opt/cellframe-node/bin/cellframe-node-cli vpn_client [start -addr <server_address> -port <server_port>|stop|status] -net <net_name>
```

Check VPN service:
```
/opt/cellframe-node/bin/cellframe-node-cli vpn_client check -addr <ip_addr> -port <port> -net <net_name>
```

### Emission Delegation Service

Create delegation:
```
/opt/cellframe-node/bin/cellframe-node-cli emit_delegate hold -net <net_name> -w <wallet_name> -token <ticker> -value <value> -fee <value> -signs_minimum <value_int> -pkey_hashes <hash1[,hash2,...,hashN]> [-tag "<str>"] [-H {hex(default) | base58}]
```

Refill delegation:
```
/opt/cellframe-node/bin/cellframe-node-cli emit_delegate refill -net <net_name> -w <wallet_name> -value <value> -fee <value> -tx <transaction_hash> [-H {hex(default) | base58}]
```

Take from delegation:
```
/opt/cellframe-node/bin/cellframe-node-cli emit_delegate take -net <net_name> -w <wallet_name> -tx <transaction_hash> -to_addr <addr1[,addr2,...,addrN]> -value <value1[,value2,...,valueN]> -fee <value> [-H {hex(default) | base58}]
```

## Token Management

### Token Declaration

Declare simple token:
```
/opt/cellframe-node/bin/cellframe-node-cli token_decl -net <net_name> [-chain <chain_name>] -token <token_ticker> -total_supply <total_supply> -signs_total <sign_total> -signs_emission <signs_for_emission> -certs <certs_list>
```

Declare CF20 token:
```
/opt/cellframe-node/bin/cellframe-node-cli token_decl -net <net_name> [-chain <chain_name>] -token <token_ticker> -type CF20 -total_supply <total_supply/if_0 =_endless> -decimals <18> -signs_total <sign_total> -signs_emission <signs_for_emission> -certs <certs_list> -flags [<Flag_1>][,<Flag_2>]...[,<Flag_N>]... [-<Param_name_1> <Param_Value_1>] [-Param_name_2> <Param_Value_2>] ...[-<Param_Name_N> <Param_Value_N>]
```

Sign token declaration:
```
/opt/cellframe-node/bin/cellframe-node-cli token_decl_sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>
```

### Token Update

```
/opt/cellframe-node/bin/cellframe-node-cli token_update -net <net_name> [-chain <chain_name>] -token <existing_token_ticker> -type <CF20|private> [-total_supply_change <value>] -certs <name_certs> [-flag_set <flag>] [-flag_unset <flag>] [-total_signs_valid <value>] [-description <value>] [-tx_receiver_allowed <value>] [-tx_receiver_blocked <value>] [-tx_sender_allowed <value>] [-tx_sender_blocked <value>] [-add_cert <name_certs>] [-remove_certs <pkeys_hash>]
```

Sign token update:
```
/opt/cellframe-node/bin/cellframe-node-cli token_update_sign -net <net_name> [-chain <chain_name>] -datum <datum_hash> -certs <certs_list>
```

### Token Emission

Create emission:
```
/opt/cellframe-node/bin/cellframe-node-cli token_emit -token <mempool_token_ticker> -emission_value <value> -addr <addr> -chain_emission <chain_name> -net <net_name> -certs <cert_list>
```

Sign emission:
```
/opt/cellframe-node/bin/cellframe-node-cli token_emit sign -emission <hash> -net <net_name> -certs <cert_list>
```

### Token Information

Get token info:
```
/opt/cellframe-node/bin/cellframe-node-cli token info -net <net_name> -name <token_ticker>
```

List coins:
```
/opt/cellframe-node/bin/cellframe-node-cli ledger list coins -net <net_name> [-limit] [-offset]
```

## Mempool Management

List mempool entries:
```
/opt/cellframe-node/bin/cellframe-node-cli mempool list -net <net_name> [-chain <chain_name>] [-addr <addr>] [-brief] [-limit] [-offset]
```

Check mempool entry:
```
/opt/cellframe-node/bin/cellframe-node-cli mempool check -net <net_name> [-chain <chain_name>] -datum <datum_hash>
```

Process mempool entry:
```
/opt/cellframe-node/bin/cellframe-node-cli mempool proc -net <net_name> [-chain <chain_name>] -datum <datum_hash>
```

Process all mempool entries:
```
/opt/cellframe-node/bin/cellframe-node-cli mempool proc_all -net <net_name> -chain <chain_name>
```

Delete mempool entry:
```
/opt/cellframe-node/bin/cellframe-node-cli mempool delete -net <net_name> [-chain <chain_name>] -datum <datum_hash>
```

## Voting and Polls

Create poll:
```
/opt/cellframe-node/bin/cellframe-node-cli poll create -net <net_name> -question <"Question_string"> -options <"Option0", "Option1" ... "OptionN"> [-expire <poll_expire_time_in_RCF822>] [-max_votes_count <Votes_count>] [-delegated_key_required] [-vote_changing_allowed] -fee <value_datoshi> -w <fee_wallet_name> [-token <ticker>]
```

Vote in poll:
```
/opt/cellframe-node/bin/cellframe-node-cli poll vote -net <net_name> -hash <poll_hash> -option_idx <option_index> [-cert <delegate_cert_name>] -fee <value_datoshi> -w <fee_wallet_name>
```

List polls:
```
/opt/cellframe-node/bin/cellframe-node-cli poll list -net <net_name>
```

Poll information:
```
/opt/cellframe-node/bin/cellframe-node-cli poll dump -net <net_name> -hash <poll_hash>
```

## Statistics

CPU statistics:
```
/opt/cellframe-node/bin/cellframe-node-cli stats cpu
```

## Troubleshooting

### Log Management

Print log:
```
/opt/cellframe-node/bin/cellframe-node-cli print_log -l_ts_after <timestamp>
```

### Diagnostic Tool

Run diagnostic tool:
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

### Service Checks

1. Check if exchange service is enabled:
   ```
   /opt/cellframe-node/bin/cellframe-node-cli srv_xchange enable
   ```

2. Check node connections:
   ```
   /opt/cellframe-node/bin/cellframe-node-cli node connections
   ```

3. Check if node has sufficient links:
   ```
   /opt/cellframe-node/bin/cellframe-node-cli net -net <network_name> get status
   ```
   (Look for active links >= required links)