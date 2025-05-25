# Cellframe Node Setup Guide

This guide provides comprehensive instructions for installing, configuring, and running a Cellframe Node, including how to set up a Master Node. It's based on our exploration of the `cellframe-node-cli` tool and available documentation.

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
   - [System Requirements](#system-requirements)
   - [Installation on Linux](#installation-on-linux)
   - [Installation on MacOS](#installation-on-macos)
   - [Installation on Windows](#installation-on-windows)
3. [Node Configuration](#node-configuration)
   - [Configuration Files](#configuration-files)
   - [Network Configuration](#network-configuration)
   - [Chain Configuration](#chain-configuration)
   - [Server Configuration](#server-configuration)
4. [Running a Node](#running-a-node)
   - [Starting the Node](#starting-the-node)
   - [Checking Node Status](#checking-node-status)
   - [Node Synchronization](#node-synchronization)
5. [Becoming a Master Node](#becoming-a-master-node)
   - [Requirements](#requirements)
   - [Staking Process](#staking-process)
   - [Master Node Validation](#master-node-validation)
   - [Earning Rewards](#earning-rewards)
6. [Security Considerations](#security-considerations)
7. [Troubleshooting](#troubleshooting)

## Introduction

A Cellframe Node is the software that allows participation in the Cellframe network. Nodes are responsible for maintaining the blockchain, processing transactions, and supporting network services such as the DEX (Decentralized Exchange), staking, and VPN.

There are two main types of nodes:
- **Light Nodes**: For basic participation and transactions
- **Master Nodes**: For network validation and earning rewards

## Installation

### System Requirements

**Minimum Requirements:**
- **CPU**: 2 cores
- **RAM**: 2GB
- **Storage**: 20GB free space
- **Network**: Stable internet connection
- **Operating System**: Linux, MacOS, or Windows

**Recommended Requirements (for Master Nodes):**
- **CPU**: 4+ cores
- **RAM**: 4GB+
- **Storage**: 50GB+ free space
- **Network**: High-speed, stable internet connection

### Installation on Linux

1. **Add the Cellframe repository:**

   For Debian/Ubuntu:
   ```bash
   sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 379CE192D401AB61
   echo "deb https://debian.cellframe.net master main" | sudo tee /etc/apt/sources.list.d/cellframe.list
   sudo apt update
   ```

2. **Install the Cellframe node package:**
   ```bash
   sudo apt install cellframe-node
   ```

3. **Verify installation:**
   ```bash
   /opt/cellframe-node/bin/cellframe-node-cli version
   ```

### Installation on MacOS

1. **Download the installation package** from the official website.

2. **Install using the package installer:**
   - Open the downloaded `.pkg` file
   - Follow the installation wizard instructions
   - Allow necessary permissions when prompted

3. **Verify installation:**
   ```bash
   /opt/cellframe-node/bin/cellframe-node-cli version
   ```

### Installation on Windows

1. **Download the Windows installer** from the official website.

2. **Run the installer:**
   - Execute the downloaded `.exe` file
   - Follow the installation wizard instructions
   - Install to the default location (recommended)

3. **Verify installation via Command Prompt:**
   ```
   "C:\Program Files\Cellframe\bin\cellframe-node-cli.exe" version
   ```

## Node Configuration

### Configuration Files

Cellframe Node uses several configuration files located in the following paths:

- **Linux/MacOS**: `/opt/cellframe-node/etc/`
- **Windows**: `C:\Program Files\Cellframe\etc\`

Key configuration files include:

- `cellframe-node.cfg`: Main configuration file
- `network/[Network Name].cfg`: Network-specific configuration
- `network/[Network Name]/chain-[Chain ID].cfg`: Chain-specific configuration
- `network/[Network Name]/main.cfg`: Main network chain configuration

### Network Configuration

The main node configuration is found in `cellframe-node.cfg`. Here are the key sections:

**1. Server Configuration:**
```ini
[server]
enabled=true
listen_address=0.0.0.0
listen_port_tcp=8079
```

**2. Stream Settings:**
```ini
[stream]
max_channels=1000
```

**3. DNS Configuration:**
```ini
[dns]
enabled=true
```

**4. Network Defaults:**
```ini
[networks]
enabled=true
```

**5. Logging Configuration:**
```ini
[logs]
log_level=2
```

**6. Resources Settings:**
```ini
[resources]
threads_cnt=0
threads_priority=0
```

### Network Configuration

Each network has its own configuration file. For example, `Backbone.cfg`:

```ini
[net]
id=0x05
name=Backbone
node-role=full
gdb_groups_prefix=backb
gdb_sync_from_zero=false
gdb_sync_request_timeout=60
```

### Chain Configuration

Each chain within a network is configured separately, for example `chain-0.cfg`:

```ini
[chain]
id=0x14
name=zerochain
consensus=dag_pos
datum_types=token,emission,signer,transaction
```

### Server Configuration

For nodes that expose JSON-RPC API or other services:

```ini
[server]
enabled=true
listen_address=0.0.0.0
listen_port_tcp=8079
```

## Running a Node

### Starting the Node

**On Linux (systemd):**
```bash
sudo systemctl start cellframe-node
sudo systemctl enable cellframe-node  # Start on boot
```

**On MacOS:**
```bash
/opt/cellframe-node/bin/cellframe-node -v
```

**On Windows:**
```
"C:\Program Files\Cellframe\bin\cellframe-node.exe" -v
```

### Checking Node Status

**Check if the node is running:**
```bash
/opt/cellframe-node/bin/cellframe-node-cli net list
```

**Check network status:**
```bash
/opt/cellframe-node/bin/cellframe-node-cli net -net Backbone get status
```

Expected output:
```
status: 
    net: Backbone
    current_addr: XXXX::XXXX::XXXX::XXXX
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

### Node Synchronization

**Initiate synchronization:**
```bash
/opt/cellframe-node/bin/cellframe-node-cli net -net Backbone sync chains
```

**Force full resynchronization:**
```bash
/opt/cellframe-node/bin/cellframe-node-cli net -net Backbone -mode all sync all
```

**Sync global database:**
```bash
/opt/cellframe-node/bin/cellframe-node-cli net -net Backbone sync -mode all gdb
```

## Becoming a Master Node

### Requirements

To become a Master Node operator, you need:

1. **Hardware**: Meet the recommended system requirements
2. **Tokens**: Hold the required amount of CELL tokens for staking
3. **Wallet**: Create and activate a wallet
4. **Network**: Ensure stable internet connectivity with a public IP or proper port forwarding

### Staking Process

1. **Create a wallet if you don't have one:**
   ```bash
   /opt/cellframe-node/bin/cellframe-node-cli wallet new -w master_wallet -sign sig_dil
   ```

2. **Activate the wallet:**
   ```bash
   /opt/cellframe-node/bin/cellframe-node-cli wallet activate -w master_wallet
   ```

3. **Create a validator stake order:**
   ```bash
   /opt/cellframe-node/bin/cellframe-node-cli srv_stake order create validator -net Backbone -value_min <minimum_stake> -value_max <maximum_stake> -tax <percent> -cert <priv_cert_name>
   ```

4. **Check your order:**
   ```bash
   /opt/cellframe-node/bin/cellframe-node-cli srv_stake order list validator -net Backbone
   ```

### Master Node Validation

Once your stake order is created, the network will validate your node. The validation process includes:

1. **Node connectivity check**: Verifies your node is reachable
2. **Stake verification**: Confirms your staked amount
3. **Certificate validation**: Validates your certificates

You can check your validation status with:
```bash
/opt/cellframe-node/bin/cellframe-node-cli srv_stake check -net Backbone -tx <tx_hash>
```

### Earning Rewards

Master Nodes earn rewards for validating transactions and maintaining the network:

1. **Reward accumulation**: Rewards accumulate based on your stake and network activity
2. **Reward distribution**: Distributed automatically to your wallet
3. **Reward checking**:
   ```bash
   /opt/cellframe-node/bin/cellframe-node-cli srv_stake reward -net Backbone -node_addr <node_address>
   ```

## Security Considerations

To maintain a secure Cellframe Node:

1. **Firewall Configuration**:
   - Allow incoming connections on the P2P port (typically 8079)
   - Restrict access to the JSON-RPC API port

2. **Certificate Management**:
   - Store certificate files securely
   - Use strong passwords for wallets
   - Consider offline certificate storage for large stakes

3. **Regular Updates**:
   ```bash
   # On Debian/Ubuntu
   sudo apt update
   sudo apt upgrade cellframe-node
   ```

4. **Log Monitoring**:
   - Check logs regularly for unusual activity
   - Logs are located in `/opt/cellframe-node/var/log/`

## Troubleshooting

### Common Issues

**1. Node Not Synchronizing**:
- Check network connectivity
- Verify port forwarding if behind a NAT
- Try forcing resynchronization:
  ```bash
  /opt/cellframe-node/bin/cellframe-node-cli net -net Backbone -mode all sync all
  ```

**2. Unable to Connect to Node**:
- Check if the node is running:
  ```bash
  ps aux | grep cellframe-node
  ```
- Restart the node service:
  ```bash
  sudo systemctl restart cellframe-node
  ```

**3. Wallet Activation Issues**:
- Verify wallet exists:
  ```bash
  /opt/cellframe-node/bin/cellframe-node-cli wallet list
  ```
- Create a new wallet if necessary

**4. Diagnostic Tool**:
- Run the diagnostic tool for detailed information:
  ```bash
  /opt/cellframe-node/bin/cellframe-diagtool -cfg
  ```

### Log Analysis

Check logs for error messages:
```bash
cat /opt/cellframe-node/var/log/cellframe-node.log | grep ERROR
```

---

This guide was created based on exploration of the `cellframe-node-cli` tool and available documentation. For the most up-to-date information, refer to the official Cellframe documentation.