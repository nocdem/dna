# CPUNK Dashboard Connector Reference Guide

## Overview

The Dashboard Connector is a JavaScript utility that provides a standardized interface for connecting to the Cellframe dashboard. It handles:

- Establishing connection to the local Cellframe node dashboard
- Wallet discovery and selection
- DNA (Distributed Naming & Addressing) identity management
- Session management with the dashboard API

## Initialization

### Basic Setup

Include the script in your HTML:
```html
<script src="js/dashboardConnector.js"></script>
```

Initialize with callbacks:
```javascript
CpunkDashboard.init({
    onConnected: function(sessionId) { 
        console.log('Connected with session:', sessionId)
    },
    onWalletSelected: function(wallet) { 
        console.log('Selected wallet:', wallet)
    },
    onDnaSelected: function(dna) { 
        console.log('Selected DNA:', dna)
    }
});
```

### Configuration Options

The `init` method accepts a configuration object with these properties:

| Option | Default | Description |
|--------|---------|-------------|
| `apiUrl` | 'http://localhost:8045/' | URL for the dashboard API |
| `dnaProxyUrl` | 'dna-proxy.php' | URL for the DNA lookup proxy |
| `statusIndicatorId` | 'statusIndicator' | ID of the status display element |
| `connectButtonId` | 'connectButton' | ID of the dashboard connect button |
| `connectionErrorId` | 'connectionError' | ID of the connection error display |
| `walletSectionId` | 'walletSection' | ID of the wallet selection section |
| `walletsListId` | 'walletsList' | ID of the wallet list container |
| `walletErrorId` | 'walletError' | ID of the wallet error display |
| `dnaSectionId` | 'dnaSection' | ID of the DNA selection section |
| `dnaListId` | 'dnaList' | ID of the DNA list container |
| `dnaErrorId` | 'dnaError' | ID of the DNA error display |
| `onConnected` | null | Callback when connection is established |
| `onWalletSelected` | null | Callback when a wallet is selected |
| `onDnaSelected` | null | Callback when a DNA identity is selected |
| `onError` | null | General error callback |

## API Methods

### Connection Management

#### `connectToDashboard()`
Establishes a connection to the Cellframe dashboard.
- Returns: Promise resolving to the sessionId
- Throws: Error if connection fails

#### `getSessionId()`
Returns the current session ID if connected.
- Returns: String or null

#### `reset()`
Resets the connection state, clears all selections.

### Wallet Management

#### `loadWallets()`
Loads all active wallets from the dashboard.
- Returns: Promise resolving to an array of wallets
- Throws: Error if wallet loading fails or not connected

#### `getWallets()`
Alias for `loadWallets()`.

#### `selectWallet(walletName)`
Selects a wallet and retrieves its details.
- Parameters:
  - `walletName`: String - Name of the wallet to select
- Returns: Promise resolving to the wallet details object
- Throws: Error if wallet selection fails

#### `getSelectedWallet()`
Returns the currently selected wallet name.
- Returns: String or null

#### `getWalletData(walletName)`
Gets detailed data for a specific wallet including network information and token balances.
- Parameters:
  - `walletName`: String - Name of the wallet
- Returns: Promise resolving to wallet data object with the following structure:
  ```json
  {
    "data": [
      {
        "address": "Rj7J7Mi...",
        "network": "Backbone",
        "tokens": [
          {
            "balance": "158.271879148362120856",
            "datoshi": "158271879148362120856",
            "tokenName": "CELL"
          },
          {
            "balance": "10136078.859612172271043647",
            "datoshi": "10136078859612172271043647",
            "tokenName": "CPUNK"
          }
        ]
      },
      {
        "address": "Rj7w51h...",
        "network": "Cpunk",
        "tokens": [
          {
            "balance": "999.9",
            "datoshi": "999900000000000000000",
            "tokenName": "tCPUNK"
          }
        ]
      }
    ],
    "status": "ok"
  }
  ```
- Throws: Error if data retrieval fails

### DNA Management

#### `loadDNAs(walletName, walletAddress)`
Loads DNA identities associated with a wallet address.
- Parameters:
  - `walletName`: String - Name of the wallet
  - `walletAddress`: String - Address of the wallet
- Returns: Promise resolving to an array of DNA identities
- Throws: Error if DNA loading fails

#### `selectDNA(dna, dnaInfo)`
Selects a DNA identity.
- Parameters:
  - `dna`: String - DNA nickname to select
  - `dnaInfo`: Object - Additional DNA information
- Returns: DNA object with additional information

#### `getSelectedDNA()`
Returns the currently selected DNA nickname.
- Returns: String or null

### API Communication

#### `makeRequest(method, params = {})`
Makes a request to the Cellframe dashboard API.
- Parameters:
  - `method`: String - API method name
  - `params`: Object - Parameters to send (optional)
- Returns: Promise resolving to the API response
- Throws: Error if the request fails

## Usage Flow

The typical usage flow follows these steps:

1. **Initialize** the dashboard connector with appropriate callbacks
2. **Connect** to the dashboard (user initiates via UI)
3. **Load wallets** (happens automatically after connection)
4. **Select wallet** (user selects from UI)
5. **Load DNAs** (happens automatically after wallet selection)
6. **Select DNA** (user selects from UI)
7. Proceed with application-specific functionality

## Example Implementation

```html
<div id="dashboard-connection">
    <div id="statusIndicator" class="status-indicator status-disconnected">Disconnected</div>
    <button id="connectButton">Connect to Dashboard</button>
    <div id="connectionError" style="display: none;"></div>
</div>

<div id="walletSection" style="display: none;">
    <h2>Select Wallet</h2>
    <div id="walletsList"></div>
    <div id="walletError" style="display: none;"></div>
</div>

<div id="dnaSection" style="display: none;">
    <h2>Select DNA Nickname</h2>
    <div id="dnaList"></div>
    <div id="dnaError" style="display: none;"></div>
</div>

<script src="js/dashboardConnector.js"></script>
<script>
    // Initialize dashboard connector
    CpunkDashboard.init({
        onConnected: function(sessionId) {
            console.log('Connected to dashboard with session:', sessionId);
        },
        onWalletSelected: function(wallet) {
            console.log('Selected wallet:', wallet.name, 'with address:', wallet.address);
        },
        onDnaSelected: function(dna) {
            console.log('Selected DNA:', dna.name);
            
            // Now perform application-specific functionality
            document.getElementById('user-dna').textContent = dna.name;
            loadUserData(dna.name);
        },
        onError: function(message, elementId) {
            console.error('Error:', message, 'in element:', elementId);
        }
    });
    
    // You can also manually invoke the connection
    document.getElementById('manual-connect').addEventListener('click', function() {
        CpunkDashboard.connectToDashboard()
            .then(sessionId => {
                console.log('Manually connected with session:', sessionId);
            })
            .catch(error => {
                console.error('Manual connection failed:', error);
            });
    });
</script>
```

## Error Handling

The connector handles several types of errors:

1. **Connection errors**: Failed connection to dashboard
2. **Wallet errors**: Problems loading or selecting wallets
3. **DNA errors**: Issues loading or selecting DNA identities
4. **API errors**: General API communication failures

Errors are:
- Displayed in the UI if error elements are present
- Logged to console
- Passed to the `onError` callback if provided
- Thrown as exceptions from Promise-based methods

## Troubleshooting

Common issues:

1. **Cannot connect to dashboard**
   - Ensure the Cellframe node is running
   - Check the `apiUrl` is correct (default: http://localhost:8045/)
   - Verify no firewall is blocking the connection

2. **No wallets displayed**
   - Ensure wallets are created in the dashboard
   - Check wallets are active (inactive wallets are filtered out)

3. **No DNA identities found**
   - Verify the wallet has registered DNA identities
   - Check the `dnaProxyUrl` is working correctly
   - Ensure the wallet address is correct

4. **Multiple initialization warnings**
   - The connector detects and warns about multiple initializations
   - Check for duplicate calls to `CpunkDashboard.init()`

## Event Sequence Diagram

```
┌──────────┐                       ┌───────────────┐                  ┌──────┐
│   Page   │                       │ DashConnector │                  │ Node │
└────┬─────┘                       └───────┬───────┘                  └──┬───┘
     │                                     │                             │
     │ CpunkDashboard.init()               │                             │
     ├─────────────────────────────────────▶                             │
     │                                     │                             │
     │ User clicks Connect Button          │                             │
     ├────────────────────────────────────▶│                             │
     │                                     │ connectToDashboard()        │
     │                                     ├────────────────────────────▶│
     │                                     │                             │
     │                                     │ sessionId                   │
     │                                     │◀────────────────────────────┤
     │                                     │                             │
     │                                     │ loadWallets()               │
     │                                     ├────────────────────────────▶│
     │                                     │                             │
     │                                     │ wallets list                │
     │                                     │◀────────────────────────────┤
     │                                     │                             │
     │ onConnected(sessionId)              │                             │
     │◀─────────────────────────────────────                             │
     │                                     │                             │
     │ User selects wallet                 │                             │
     ├────────────────────────────────────▶│                             │
     │                                     │ selectWallet()              │
     │                                     ├────────────────────────────▶│
     │                                     │                             │
     │                                     │ wallet data                 │
     │                                     │◀────────────────────────────┤
     │                                     │                             │
     │                                     │ loadDNAs()                  │
     │                                     ├────────────────────────────▶│
     │                                     │                             │
     │                                     │ DNA list                    │
     │                                     │◀────────────────────────────┤
     │                                     │                             │
     │ onWalletSelected(wallet)            │                             │
     │◀─────────────────────────────────────                             │
     │                                     │                             │
     │ User selects DNA                    │                             │
     ├────────────────────────────────────▶│                             │
     │                                     │ selectDNA()                 │
     │                                     │───────────────────┐         │
     │                                     │                   │         │
     │                                     │◀──────────────────┘         │
     │                                     │                             │
     │ onDnaSelected(dna)                  │                             │
     │◀─────────────────────────────────────                             │
     │                                     │                             │
```

## Security Considerations

1. The connector communicates with a local Cellframe node. Ensure the node is properly secured.
2. The API should only be exposed to trusted sources (ideally localhost only).
3. The connector does not handle wallet passwords or private keys; these remain secure in the dashboard.