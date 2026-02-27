# Cellframe Developer Reference

This document provides a developer-focused reference for working with the Cellframe platform, combining information from our research and available documentation. It covers advanced topics including architecture, token standards, transactions, JSON-RPC APIs, and Python plugins.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [CF-20 Token Standard](#cf-20-token-standard)
3. [Transaction Types](#transaction-types)
   - [Conditional Transactions](#conditional-transactions)
4. [JSON-RPC API](#json-rpc-api)
   - [Introduction](#json-rpc-introduction)
   - [Web3 API Compatibility](#web3-api-compatibility)
   - [Cellframe Tool Sign](#cellframe-tool-sign)
5. [Python Plugins](#python-plugins)
   - [Plugin System Overview](#plugin-system-overview)
   - [Plugin Levels](#plugin-levels)
6. [Development Resources](#development-resources)

## Architecture Overview

Cellframe is designed with a multi-layered architecture that provides both flexibility and security:

### Layer Structure

1. **Layer 0 (Network Layer)**
   - Ensures compatibility across different chains and protocols
   - Decentralized peer-to-peer mesh network
   - Foundation for creating parachains

2. **Layer 1 (Fundamental Layer)**
   - Handles basic blockchain functions
   - Uses ESBOCS consensus (based on Catchain)
   - Operates on a Proof of Stake (PoS) principle
   - Implements the dual-layer sharding structure
   - Provides post-quantum cryptography

3. **Layer 2 (Execution Layer)**
   - Handles scaling beyond the main chain
   - Manages execution of conditional transactions
   - Handles cross-chain operations

4. **Layer 3 (Application Layer)**
   - Supports creation of decentralized applications (t-dApps)
   - Provides t-dApps library
   - Interfaces with external services

### Dual-Layer Sharding

Cellframe's unique sharding implementation includes:

1. **Heterogeneous Layer (First Level)**
   - Divides the network into sets of nodes and chains
   - Allows customization of subchains and tokens
   - Caters to specific application needs

2. **Homogeneous Layer (Second Level)**
   - Organizes subchains into "Cells"
   - Improves network scalability and resilience

### Directed Acyclic Graph (DAG)

The DAG structure is used in Cellframe's zero-chain:

- Events are organized in a directed graph without cycles
- Each event contains only one data type (datum)
- Events form connected graphs called "Rounds"
- Rounds are initially placed in the Global Database (GDB)
- After a minimum time has passed, connected rounds are moved from GDB to chains
- Provides higher throughput compared to traditional blockchain designs
- Can process up to 500,000 transactions per second (potentially up to 1 million)

## CF-20 Token Standard

The CF-20 token standard is Cellframe's token implementation framework, which defines how tokens operate on the platform:

### Key Features

- **Post-Quantum Security**: Inherits Cellframe's quantum-resistant cryptography
- **Customizable Supply**: Can be limited or unlimited (set with `total_supply` parameter)
- **Decimal Precision**: Configurable decimal places (commonly 18)
- **Flexible Permissions**: Granular control over token operations
- **Multi-signature Support**: Requires specified number of signatures for operations

### Token Declaration

CF-20 tokens are declared using the following command structure:

```bash
/opt/cellframe-node/bin/cellframe-node-cli token_decl -net <net_name> [-chain <chain_name>] -token <token_ticker> -type CF20 -total_supply <total_supply/if_0 =_endless> -decimals <18> -signs_total <sign_total> -signs_emission <signs_for_emission> -certs <certs_list> -flags [<Flag_1>][,<Flag_2>]...[,<Flag_N>]... [-<Param_name_1> <Param_Value_1>] [-Param_name_2> <Param_Value_2>] ...[-<Param_Name_N> <Param_Value_N>]
```

### Token Flags

CF-20 tokens can be configured with various flags that determine their behavior:

- `ALL_FROZEN`: All token transfers are frozen
- `ALL_EMISSIONS_FROZEN`: No new tokens can be created
- `ALL_DEFROSTING_FROZEN`: Frozen tokens cannot be unfrozen
- `STATIC_PERMISSIONS`: Token permissions cannot be changed
- `STATIC_EMISSIONS`: Emissions parameters cannot be modified
- `STATIC_FLAGS`: Flags cannot be modified
- `AUTO_EMISSIONS`: Allows automatic token emissions

### Token Emission

After declaration, tokens can be created through emission:

```bash
# Create emission
/opt/cellframe-node/bin/cellframe-node-cli token_emit -token <mempool_token_ticker> -emission_value <value> -addr <addr> -chain_emission <chain_name> -net <net_name> -certs <cert_list>

# Sign emission
/opt/cellframe-node/bin/cellframe-node-cli token_emit sign -emission <hash> -net <net_name> -certs <cert_list>
```

### Token Updates

CF-20 tokens can be updated after creation to modify properties:

```bash
/opt/cellframe-node/bin/cellframe-node-cli token_update -net <net_name> [-chain <chain_name>] -token <existing_token_ticker> -type CF20 [-total_supply_change <value>] -certs <name_certs> [-flag_set <flag>] [-flag_unset <flag>] [-total_signs_valid <value>] [-description <value>] [-tx_receiver_allowed <value>] [-tx_receiver_blocked <value>] [-tx_sender_allowed <value>] [-tx_sender_blocked <value>] [-add_cert <name_certs>] [-remove_certs <pkeys_hash>]
```

## Transaction Types

Cellframe supports various transaction types for different purposes:

### Basic Transactions

```bash
# Create a basic transaction
/opt/cellframe-node/bin/cellframe-node-cli tx_create -net <net_name> [-chain <chain_name>] -value <value> -token <token_ticker> -to_addr <addr> {-from_wallet <wallet_name> | -from_emission <emission_hash> {-cert <cert_name> | -wallet_fee <wallet_name>}} -fee <value>
```

### Conditional Transactions

Conditional transactions are a key Cellframe innovation that provides smart contract-like functionality without traditional smart contracts.

#### Key Features

- Act as decentralized escrow mechanisms
- Execute based on predefined conditions
- Used by DEX and other services
- More efficient than traditional smart contracts
- Support complex multi-party workflows

#### Creating Conditional Transactions

```bash
# Create conditional transaction
/opt/cellframe-node/bin/cellframe-node-cli tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name> -cert <pub_cert_name> -value <value_datoshi> -fee <value> -unit {B | SEC} -srv_uid <numeric_uid>
```

Parameters:
- `net_name`: Network name (e.g., Backbone, KelVPN)
- `token_ticker`: Token to use
- `wallet_name`: Wallet providing the funds
- `pub_cert_name`: Certificate for receiving funds
- `value_datoshi`: Amount in smallest units
- `fee`: Transaction fee
- `unit`: Time units (B for blocks, SEC for seconds)
- `srv_uid`: Service unique identifier

#### Usage in DEX

In Cellframe's DEX, conditional transactions store the terms of exchange. When a user creates an order, a conditional transaction is created with terms that automatically execute when matching conditions are met.

#### Example Service Integration

```bash
# Check conditional transaction
/opt/cellframe-node/bin/cellframe-node-cli tx_cond_verify -net <net_name> -tx <tx_hash>
```

## JSON-RPC API

### JSON-RPC Introduction

Cellframe provides a JSON-RPC API for interacting with the node programmatically:

#### Basic Configuration

The JSON-RPC server settings can be found in the node configuration file:
```
[server]
enabled=true
listen_address=0.0.0.0
listen_port_tcp=8079
```

#### Authentication

Access requires an auth key which can be configured in:
```
[server]
auth_type=dap
auth_key=<key>
```

#### Making Requests

Requests follow standard JSON-RPC 2.0 format:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "method_name",
  "params": {
    "param1": "value1",
    "param2": "value2"
  }
}
```

#### Example Request

```bash
curl -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "wallet_list",
  "params": {}
}' http://localhost:8079
```

### Web3 API Compatibility

Cellframe provides Web3 API compatibility to make it easier for Ethereum developers to integrate with the platform:

#### Supported Methods

- `eth_blockNumber`: Get current block number
- `eth_getBalance`: Get wallet balance
- `eth_accounts`: List available accounts
- `eth_call`: Execute a call without creating a transaction
- `eth_sendTransaction`: Create and broadcast a transaction
- `eth_getTransactionReceipt`: Get transaction receipt
- `eth_getTransactionByHash`: Get transaction by hash

#### Example: Getting Balance

```bash
curl -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_getBalance",
  "params": ["0x1234...", "latest"]
}' http://localhost:8079
```

### Cellframe Tool Sign

The Cellframe Tool Sign provides functionality for transaction signing:

#### Key Features

- Offline transaction signing
- Multi-signature support
- Quantum-resistant signing algorithms
- Integration with hardware wallets

#### Usage Examples

```bash
# Sign a transaction
cellframe-tool-sign -file tx.dat -cert my_cert -out signed_tx.dat

# Verify a signature
cellframe-tool-sign -verify -file signed_tx.dat
```

## Python Plugins

### Plugin System Overview

Cellframe provides a Python plugin system for extending node functionality:

#### Key Features

- Extends node functionality without modifying core code
- Support for both built-in and third-party plugins
- Access to Cellframe SDK via Python bindings
- Event-driven architecture for callbacks
- Persistent storage for plugin data

#### Plugin Structure

A basic plugin has the following structure:

```python
import cellframe_python

def init():
    # Initialization code
    return 0

def deinit():
    # Cleanup code
    return 0

def process(arg):
    # Processing logic
    return 0
```

### Plugin Levels

Cellframe Python plugins operate at different levels, each with different access and capabilities:

#### System Level Plugins

- Highest level of access
- Can interact with core node functionality
- Can modify service behavior
- Require admin permissions to install

#### Network Level Plugins

- Network-specific functionality
- Can interact with network data
- Restricted to operations within a specific network
- Cannot modify core node behavior

#### Chain Level Plugins

- Chain-specific operations
- Access to blockchain data for a specific chain
- Can implement custom consensus features
- Limited to operations within a single chain

#### Service Level Plugins

- Extend existing Cellframe services
- Add new service capabilities
- Custom business logic for services
- Moderate level of node access

#### Implementation Example

```python
import cellframe_python as cp

# Plugin metadata
PLUGIN_NAME = "my_custom_plugin"
PLUGIN_LEVEL = cp.PLUGIN_LEVEL_NETWORK

def init():
    cp.log_info("Initializing {} plugin".format(PLUGIN_NAME))
    # Register for events
    cp.add_callback(cp.EVENT_TYPE_TX, tx_callback)
    return 0

def deinit():
    cp.log_info("Shutting down {} plugin".format(PLUGIN_NAME))
    return 0

def tx_callback(event):
    tx_hash = event.get_data("tx_hash")
    cp.log_info("New transaction: {}".format(tx_hash))
    # Custom processing logic
    return 0
```

## Development Resources

### Official Resources

- **Cellframe Wiki**: https://wiki.cellframe.net/
- **GitHub Repository**: https://github.com/cellframe/cellframe-node
- **API Documentation**: https://docs.cellframe.net/

### Development Tools

- **cellframe-node-cli**: Command-line interface for node management
- **cellframe-node-tool**: Certificate and wallet management tool
- **cellframe-tool-sign**: Transaction signing utility
- **cellframe-diagtool**: Diagnostic and debugging tool

### Cellframe SDK Components

- **libdap**: Core libraries for Cellframe node
- **libdap-python**: Python bindings for Cellframe SDK
- **libdap-chain**: Blockchain implementation
- **libdap-chain-net**: Network layer implementation
- **libdap-chain-wallet**: Wallet management
- **libdap-chain-global-db**: Global database functionality

This developer reference is based on our exploration of the Cellframe platform and available documentation. For the most up-to-date information, please refer to the official Cellframe documentation.