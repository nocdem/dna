# CPUNK Single Sign-On (SSO) Reference

## Overview

The CPUNK platform uses a centralized Single Sign-On (SSO) system that manages user authentication across all pages. The SSO module handles dashboard connection, wallet selection, and DNA identity management in one unified flow.

## Core Components

### SSO Module (`/js/sso.js`)

The main SSO module that provides:
- Singleton pattern for consistent state across pages
- Dashboard connection management
- Wallet selection and validation
- DNA identity retrieval
- Session storage management
- Navbar state updates

### Authentication Module (`/js/authentication.js`)

Handles the login flow:
- Dashboard connection
- Wallet selection UI
- DNA verification
- Session creation

## Usage

### Basic Implementation

```javascript
// Initialize SSO on page load
document.addEventListener('DOMContentLoaded', () => {
    const sso = CpunkSSO.getInstance();
    sso.init({
        onAuthenticated: (user) => {
            console.log('User authenticated:', user.dna);
            // User is logged in, show authenticated content
        },
        onUnauthenticated: () => {
            console.log('User not authenticated');
            // Show login required message
        }
    });
});
```

### Accessing User Data

```javascript
const sso = CpunkSSO.getInstance();

// Check authentication status
if (sso.isAuthenticated()) {
    // Get user DNA
    const userDna = sso.getUserDna();
    
    // Get wallet info
    const walletInfo = sso.getWalletInfo();
    // Returns: { name, address, network, cpunkBalance }
    
    // Get session ID for dashboard API calls
    const sessionId = sso.getSessionId();
}
```

### Logout

```javascript
const sso = CpunkSSO.getInstance();
sso.logout(); // Clears session and redirects to home
```

## Session Storage

SSO stores the following in sessionStorage:
- `cpunk_session_id` - Dashboard session ID
- `cpunk_user_dna` - User's DNA identity
- `cpunk_wallet_address` - Selected wallet address
- `cpunk_wallet_name` - Selected wallet name
- `cpunk_wallet_network` - Network (always "Backbone")
- `cpunk_wallet_balance` - CPUNK balance

## Page Implementation Examples

### Login Required Page

```html
<!-- HTML -->
<div id="loginRequiredSection" class="section" style="display: none;">
    <div class="info-section">
        <p>Please login to access this feature.</p>
        <button id="loginBtn" class="btn btn-primary">Login</button>
    </div>
</div>

<div id="authenticatedContent" style="display: none;">
    <!-- Page content for authenticated users -->
</div>
```

```javascript
// JavaScript
document.addEventListener('DOMContentLoaded', () => {
    const sso = CpunkSSO.getInstance();
    sso.init({
        onAuthenticated: (user) => {
            document.getElementById('loginRequiredSection').style.display = 'none';
            document.getElementById('authenticatedContent').style.display = 'block';
            
            // Use wallet info from SSO
            const walletInfo = sso.getWalletInfo();
            console.log('Using wallet:', walletInfo.name, walletInfo.address);
        },
        onUnauthenticated: () => {
            document.getElementById('loginRequiredSection').style.display = 'block';
            document.getElementById('authenticatedContent').style.display = 'none';
        }
    });
    
    // Login button handler
    document.getElementById('loginBtn')?.addEventListener('click', () => {
        window.location.href = 'login.html?redirect=' + window.location.pathname;
    });
});
```

### Making Dashboard API Calls

```javascript
const sso = CpunkSSO.getInstance();
const sessionId = sso.getSessionId();

if (sessionId) {
    // Make dashboard API request
    const response = await makeRequest('SendTransaction', {
        id: sessionId,
        net: 'Backbone',
        walletName: sso.getWalletInfo().name,
        toAddr: recipientAddress,
        tokenName: 'CPUNK',
        value: amount
    });
}
```

## Navbar Integration

The SSO module automatically updates the navbar to show:
- "Login" link when not authenticated
- User's DNA name when authenticated

This happens automatically when SSO is initialized on any page.

## Benefits

1. **Unified Authentication**: One login flow for entire platform
2. **Persistent Session**: Stay logged in across page navigation
3. **Automatic Wallet Selection**: No need to select wallet on each page
4. **DNA Identity**: User's DNA is available on all pages
5. **Simplified Implementation**: Easy to add authentication to any page
6. **Consistent State**: All pages share the same authentication state

## Security Considerations

- Session data is stored in sessionStorage (cleared on browser close)
- No sensitive data (private keys, passwords) is stored
- Dashboard connection requires local wallet software
- Session expires when dashboard is disconnected

## Migration Guide

For pages using old dashboard connection:

### Before (Direct Dashboard Connection)
```javascript
// Old approach - each page handles its own connection
async function connectToDashboard() {
    const response = await makeRequest('Connect');
    sessionId = response.data.id;
    // Load wallets, handle selection, etc.
}
```

### After (Using SSO)
```javascript
// New approach - SSO handles everything
const sso = CpunkSSO.getInstance();
sso.init({
    onAuthenticated: (user) => {
        // Ready to use - wallet and DNA already selected
        const sessionId = sso.getSessionId();
        const walletInfo = sso.getWalletInfo();
    }
});
```

## Pages Using SSO

- `login.html` - Main authentication page
- `settings.html` - User settings and profile
- `board.html` - Community board
- `mainnet_party.html` - Event registration
- Additional pages being migrated...