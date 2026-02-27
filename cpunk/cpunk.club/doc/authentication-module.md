# CPUNK Authentication Module

## Overview

The CPUNK Authentication Module (`js/authentication.js`) provides centralized authentication functionality for admin-protected pages. It handles dashboard connection, wallet selection, DNA verification, and admin authorization.

## Features

- Automatic dashboard connection management
- Wallet selection UI
- DNA lookup and admin verification
- Session management with logout functionality
- Consistent UI/UX across all admin pages

## Usage

### 1. Include Required Scripts

```html
<script src="js/dashboardConnector.js"></script>
<script src="js/authentication.js"></script>
```

### 2. Initialize the Module

```javascript
await CpunkAuth.init({
    onAuthenticated: function(authData) {
        // Called when admin is successfully authenticated
        console.log('Admin authenticated:', authData);
        // authData contains: { dna, wallet, allDnas, adminDnas }
    },
    onAccessDenied: function(message) {
        // Called when user is not an admin
        console.log('Access denied:', message);
    },
    onError: function(message) {
        // Called on any error
        console.error('Error:', message);
    },
    onLogout: function() {
        // Called when user logs out
        console.log('User logged out');
    }
});
```

### 3. Required HTML Elements

The module expects these elements in your HTML:

```html
<!-- Connection Status Section -->
<div class="status-section" id="connect-section">
    <div class="status-box">
        <div class="status-header">
            <span>Dashboard Status:</span>
            <span class="status-indicator status-disconnected" id="statusIndicator">Disconnected</span>
        </div>
        <button id="connectButton" class="help-button">Connect</button>
    </div>
    <div id="connectionError" class="message error" style="display: none;"></div>
</div>

<!-- Wallet Selection Section -->
<div class="status-section" id="walletSection" style="display: none;">
    <h3>Select Wallet for Admin Access</h3>
    <p>Choose the wallet containing your admin DNA.</p>
    <div id="walletsList"></div>
    <div id="walletError" class="message error" style="display: none;"></div>
</div>

<!-- Admin Check Status -->
<div id="dnaError" class="message error" style="display: none;"></div>

<!-- Your authenticated content here -->
<div id="your-content" style="display: none;">
    <!-- Content shown after successful authentication -->
</div>
```

### 4. Disconnect Button

Add a disconnect button in your authenticated area:

```html
<button id="logoutButton" style="background-color: var(--error); color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer;">
    Disconnect from Dashboard
</button>
```

## Authentication Flow

1. User clicks "Connect" button
2. Module connects to Cellframe dashboard (localhost:8045)
3. User selects a wallet
4. Module checks if wallet has DNA registration
5. Module verifies if DNA is in admin list (`admins.txt`)
6. If admin, `onAuthenticated` callback is triggered
7. If not admin, `onAccessDenied` callback is triggered

## Admin List

The module reads admin DNA nicknames from `admins.txt` file. Each line should contain one admin DNA nickname:

```
nocdem
ADST
VBorisov
```

## Session Management

- Session data is stored in browser's `sessionStorage`
- Logout clears all cached data and session storage
- Disconnect button properly resets the authentication state

## API Methods

### `CpunkAuth.init(config)`
Initialize the authentication module with callbacks.

### `CpunkAuth.connect()`
Manually trigger dashboard connection (usually handled by button click).

### `CpunkAuth.logout()`
Logout and clear all session data.

### `CpunkAuth.getStatus()`
Get current authentication status:
```javascript
{
    isAuthenticated: boolean,
    dna: string,
    wallet: string,
    sessionId: string
}
```

## Example Implementation

See `admin.html` and `editor.html` for complete implementation examples.

## Error Handling

The module handles various error scenarios:
- Dashboard not running
- No wallets available
- No DNA registration
- Non-admin DNA
- Network errors

All errors are passed to the `onError` callback with descriptive messages.