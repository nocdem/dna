# JavaScript Structure

## Overview

The JavaScript for the CPUNK platform has been restructured to use shared utility libraries for common functionality, improving code organization, reducing duplication, and enhancing maintainability.

## Core Utility Libraries

- `cpunk-utils.js`: Core utility functions for common operations
- `cpunk-transaction.js`: Transaction management and verification utilities
- `cpunk-ui.js`: UI components and helpers

## Using the Libraries

Include the utility libraries before your page-specific scripts:

```html
<head>
    <!-- Other head elements -->
    
    <!-- First include the utility libraries -->
    <script src="js/cpunk-utils.js"></script>
    <script src="js/cpunk-transaction.js"></script>
    <script src="js/cpunk-ui.js"></script>
    
    <!-- Then include the page-specific script -->
    <script src="js/register.js"></script>
</head>
```

## Library Documentation

### CpunkUtils

Core utilities for common operations:

- **API Communication**
  - `dashboardRequest(method, params)`: Make requests to the Cellframe dashboard API
  - `dnaLookup(action, value)`: Query the DNA API for lookups and verifications
  - `dnaPost(data)`: Send POST requests to the DNA API

- **Validation & Calculations**
  - `isValidNicknameFormat(nickname)`: Check if a DNA nickname has a valid format
  - `calculateDnaPrice(nickname)`: Calculate price for DNA registration
  - `calculateDelegationTax(amount)`: Calculate delegation tax rate
  - `formatBalance(balance, decimals)`: Format token balances for display

- **DNA Operations**
  - `checkDnaRegistration(address)`: Check if an address is registered in DNA
  - `checkNicknameAvailability(nickname)`: Check if a nickname is available
  - `registerDna(params)`: Register a DNA nickname
  - `recordDelegation(params)`: Record delegation in DNA profile

- **Transaction Management**
  - `verifyTransaction(txHash)`: Verify a transaction by its hash
  - `startTransactionVerification(txHash, callbacks)`: Start verification process
  - `clearVerificationTimers(timers)`: Clear verification timers

- **Utility Functions**
  - `copyToClipboard(text, callbacks)`: Copy text to clipboard
  - `logDebug(message, type, data)`: Log debug information
  - `formatJsonForHtml(obj)`: Format JSON with syntax highlighting

### CpunkTransaction

Transaction management utilities:

- **Configuration**
  - `init(customConfig)`: Initialize with custom configuration
  - `setSessionId(id)`: Set dashboard API session ID

- **Transaction Operations**
  - `sendTransaction(params)`: Send a transaction via dashboard API
  - `createStakingOrder(params)`: Create a staking order
  - `startVerification(params)`: Start transaction verification
  - `verifyTransaction(txHash)`: Verify a transaction by hash

### CpunkUI

UI components and helpers:

- **Status Management**
  - `updateConnectionStatus(status, message)`: Update connection status display
  - `showError(message, elementId, timeout)`: Show error message
  - `hideError(elementId)`: Hide error message
  - `setLoading(isLoading, elementId)`: Show/hide loading indicator

- **UI Components**
  - `createWalletCard(wallet, onSelect)`: Create wallet card for display
  - `createDnaCard(dnaName, dnaInfo, onSelect)`: Create DNA card for display
  - `createVerificationUI(txHash, orderHash)`: Create transaction verification UI
  - `updateVerificationUI(status, params)`: Update verification UI based on status
  - `copyHash(hash, buttonElement)`: Copy hash to clipboard

## Benefits

This JavaScript restructuring provides several benefits:

1. **Reduced Code Duplication**: Common functions like API calls and transaction verification are defined once
2. **Better Maintenance**: Changes to shared functionality only need to be made in one place
3. **Consistent Behavior**: Ensures consistent handling of errors, transactions, and API calls
4. **Clearer Organization**: Separates UI, transaction handling, and utility functions
5. **Easier Testing**: Isolated functions are easier to test

## Implementation Notes

When implementing this in production:

1. First add the utility libraries to the HTML (as shown above)
2. Then gradually refactor page-specific scripts to use the utilities
3. Thoroughly test each page after refactoring
4. Consider adding unit tests for the utility functions