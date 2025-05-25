# CPUNK OAuth Implementation Guide

This document outlines the standardized approach for implementing OAuth authentication mechanisms for the CPUNK platform.

## OAuth Implementation Pattern

All OAuth implementations in the CPUNK platform should follow this consistent pattern:

### 1. Client-Side Button Handler (in login.html)

```javascript
// Example for ServiceName OAuth
const connectServiceButton = document.getElementById('connectServiceButton');
if (connectServiceButton) {
    connectServiceButton.addEventListener('click', function(e) {
        // Prevent default button behavior
        e.preventDefault();

        // Check for wallet address
        if (!walletAddress) {
            // Show error message
            if (saveError) {
                saveError.textContent = 'Wallet address is missing. Please select a wallet first.';
                saveError.style.display = 'block';
            }
            return;
        }

        // Disable the button during OAuth
        connectServiceButton.disabled = true;
        connectServiceButton.innerHTML = '<span class="loading-spinner"></span>Connecting...';

        // Open popup for OAuth
        const width = 600;
        const height = 600;
        const left = window.screen.width / 2 - width / 2;
        const top = window.screen.height / 2 - height / 2;
        const features = `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no,location=no`;

        // Open the popup with wallet parameter
        const SERVICE_OAUTH_URL = 'service_oauth.php';
        const authUrl = `${SERVICE_OAUTH_URL}?request=auth&wallet=${encodeURIComponent(walletAddress)}`;
        
        const popup = window.open(authUrl, 'serviceAuth', features);

        // Check if popup was blocked
        if (!popup || popup.closed || typeof popup.closed === 'undefined') {
            console.error('Popup window was blocked or failed to open');
            if (saveError) {
                saveError.textContent = 'Please allow popups for this site to use Service authentication';
                saveError.style.display = 'block';
            }
            
            // Reset button
            connectServiceButton.disabled = false;
            connectServiceButton.innerHTML = 'Connect Service';
        }
        
        // Listen for messages from the popup
        window.addEventListener('message', handleServiceAuthCallback);
    });
}
```

### 2. Client-Side Callback Handler

```javascript
// Handle Service OAuth callback
async function handleServiceAuthCallback(event) {
    // Verify the origin
    if (event.origin !== window.location.origin) {
        console.warn('Received message from unknown origin', event.origin);
        return;
    }
    
    console.log('Received Service auth callback:', event.data);
    
    if (event.data.type === 'service_auth_success') {
        // Success - Service account connected
        const username = event.data.username; // Or equivalent identifier
        
        // Update the UI
        const serviceProfileInput = document.getElementById('serviceProfile');
        if (serviceProfileInput) serviceProfileInput.value = username;
        
        // Update verification status
        const serviceVerificationStatus = document.getElementById('serviceVerificationStatus');
        if (serviceVerificationStatus) {
            serviceVerificationStatus.innerHTML = `
                <div class="status-circle status-verified"></div>
                <span class="status-text">Verified</span>
            `;
        }

        // Hide the connect button completely when verified
        const connectServiceButton = document.getElementById('connectServiceButton');
        if (connectServiceButton) {
            connectServiceButton.style.display = 'none';
        }

        // Hide the help text for verified accounts
        const serviceHelpText = connectServiceButton ?
            connectServiceButton.parentElement.nextElementSibling : null;
        if (serviceHelpText && serviceHelpText.classList.contains('help-text')) {
            serviceHelpText.style.display = 'none';
        }
        
        // Show success message
        if (saveSuccess) {
            saveSuccess.textContent = `Service account ${username} connected successfully!`;
            saveSuccess.style.display = 'block';
        }
        if (saveError) saveError.style.display = 'none';
        
        // Update social count
        setTimeout(updateSocialCount, 500);
        
        // Refresh data to get latest changes
        await checkDnaRegistration();
        
    } else if (event.data.type === 'service_auth_error') {
        // Error occurred during auth
        console.error('Service auth error:', event.data.error);
        
        // Reset button
        const connectServiceButton = document.getElementById('connectServiceButton');
        if (connectServiceButton) {
            connectServiceButton.disabled = false;
            connectServiceButton.style.display = 'block';
            connectServiceButton.innerHTML = 'Connect Service';

            // Ensure help text is visible
            const serviceHelpText = connectServiceButton ?
                connectServiceButton.parentElement.nextElementSibling : null;
            if (serviceHelpText && serviceHelpText.classList.contains('help-text')) {
                serviceHelpText.style.display = '';
            }
        }
        
        // Show error message
        if (saveError) {
            saveError.textContent = `Error connecting Service: ${event.data.error}`;
            saveError.style.display = 'block';
        }
        if (saveSuccess) saveSuccess.style.display = 'none';
    }
    
    // Clean up event listener
    window.removeEventListener('message', handleServiceAuthCallback);
}
```

### 3. Server-Side OAuth Handler (service_oauth.php)

```php
<?php
/**
 * Service OAuth Handler for CPUNK
 * This file handles the OAuth process for Service
 */

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Log file for debugging
$logFile = 'service_oauth_log.txt';
function logMsg($message) {
    global $logFile;
    file_put_contents($logFile, date('[Y-m-d H:i:s] ') . $message . PHP_EOL, FILE_APPEND);
}

logMsg('Service OAuth process started');

// Allow cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Service API credentials
define('CLIENT_ID', 'your_client_id_here');
define('CLIENT_SECRET', 'your_client_secret_here');
define('OAUTH_CALLBACK', 'https://' . $_SERVER['HTTP_HOST'] . '/service_oauth.php');

// DNA API endpoint - use absolute URL
define('DNA_API_URL', 'https://' . $_SERVER['HTTP_HOST'] . '/dna-proxy.php');

// Initialize session to store OAuth tokens and wallet address
session_start();

// Handle the initial OAuth request
if (isset($_GET['request']) && $_GET['request'] == 'auth') {
    logMsg('Starting auth request. Wallet: ' . ($_GET['wallet'] ?? 'not provided'));
    
    // Store wallet address in session
    if (isset($_GET['wallet'])) {
        $_SESSION['wallet_address'] = $_GET['wallet'];
        logMsg('Stored wallet address in session: ' . $_GET['wallet']);
    }
    
    // Build authorization URL and redirect to service
    // ...Service-specific OAuth initialization code...
}

// Handle the callback from Service
if (isset($_GET['code']) || isset($_GET['oauth_token'])) {
    // ...Service-specific OAuth callback handling...
    
    // After successful OAuth, get the user info from Service
    // ...Service-specific user info retrieval...
    
    // Get wallet address from session or query parameter
    $walletAddress = '';
    if (isset($_SESSION['wallet_address'])) {
        $walletAddress = $_SESSION['wallet_address'];
        logMsg('Got wallet address from session: ' . $walletAddress);
    } elseif (isset($_GET['wallet'])) {
        $walletAddress = $_GET['wallet'];
        logMsg('Got wallet address from query param: ' . $walletAddress);
    }
    
    // If we have a wallet address, update DNA
    $result = [];
    if (!empty($walletAddress) && !empty($username)) {
        logMsg('Updating DNA with Service username: ' . $username . ' for wallet: ' . $walletAddress);
        $result = updateDnaService($walletAddress, $username);
        logMsg('DNA update result: ' . json_encode($result));
    } else {
        logMsg('No wallet address or username available for DNA update');
    }
    
    // Send result back to opener window and close
    echo "<script>
        window.opener.postMessage({
            type: 'service_auth_success',
            username: " . json_encode($username) . ",
            result: " . json_encode($result) . "
        }, '*');
        window.close();
    </script>";
    exit;
}

/**
 * Update the user's DNA record with their Service username
 */
function updateDnaService($walletAddress, $serviceUsername) {
    // Prepare data for update
    $updateData = [
        'action' => 'update',
        'wallet' => $walletAddress,
        'socials' => [
            'service_key' => [
                'profile' => $serviceUsername,
                'verified' => true
            ]
        ]
    ];
    
    // Make POST request to update DNA
    // ...DNA API call implementation...
    
    // Return result
    return $result;
}

// Default response for direct access
// ...HTML page for direct access...
?>
```

### 4. Update Social Count Function

Make sure that the `updateSocialCount()` function includes the new service in its count:

```javascript
// Helper function to update social count
function updateSocialCount() {
    const socialsCountElement = document.getElementById('socialsCount');
    if (socialsCountElement) {
        let verifiedCount = 0;

        // Check Twitter verification
        // [existing code]

        // Check Telegram verification
        // [existing code]
        
        // Check Google verification
        // [existing code]
        
        // Check New Service verification
        const serviceStatus = document.querySelector('#serviceVerificationStatus .status-text');
        const serviceCircle = document.querySelector('#serviceVerificationStatus .status-circle');
        const serviceProfile = document.getElementById('serviceProfile');

        if ((serviceStatus && serviceStatus.textContent === 'Verified') ||
            (serviceCircle && serviceCircle.classList.contains('status-verified')) ||
            (serviceProfile && serviceProfile.value && serviceProfile.value !== 'Not connected')) {
            verifiedCount++;
            console.log('Service verified - count:', verifiedCount);
        }

        // Update the count and log it
        socialsCountElement.textContent = verifiedCount;
        console.log('Final social count:', verifiedCount);
    }
}
```

### 5. Verification Status Function

Create a dedicated function to manage the verification status UI, which gets called both on initial load and when the verification status changes:

```javascript
// Update Service verification status UI
function updateServiceVerificationStatus(serviceData) {
    // Get DOM elements
    const serviceVerificationStatus = document.getElementById('serviceVerificationStatus');
    const serviceProfileInput = document.getElementById('serviceProfile');
    const connectServiceButton = document.getElementById('connectServiceButton');

    // Get help text element (usually the div.help-text after the button's parent)
    const serviceHelpText = connectServiceButton ?
        connectServiceButton.parentElement.nextElementSibling : null;

    if (!serviceVerificationStatus) return;

    if (serviceData && serviceData.profile) {
        // If there's a profile, consider it verified
        serviceVerificationStatus.innerHTML = `
            <div class="status-circle status-verified"></div>
            <span class="status-text">Verified</span>
        `;

        // Update input field with profile data
        if (serviceProfileInput) {
            serviceProfileInput.value = serviceData.profile;
        }

        // Hide the connect button completely
        if (connectServiceButton) {
            connectServiceButton.style.display = 'none';
        }

        // Hide the help text
        if (serviceHelpText && serviceHelpText.classList.contains('help-text')) {
            serviceHelpText.style.display = 'none';
        }
    } else {
        // Not verified
        serviceVerificationStatus.innerHTML = `
            <div class="status-circle status-unverified"></div>
            <span class="status-text">Not connected</span>
        `;

        // Clear input field
        if (serviceProfileInput) {
            serviceProfileInput.value = '';
        }

        // Show connect button
        if (connectServiceButton) {
            connectServiceButton.style.display = 'block';
            connectServiceButton.disabled = false;
            // Reset button to original state
            connectServiceButton.innerHTML = 'Connect Service';
        }

        // Show help text
        if (serviceHelpText && serviceHelpText.classList.contains('help-text')) {
            serviceHelpText.style.display = '';
        }
    }
}
```

Call this function in these situations:
1. In the `populateForm` function when loading initial data:
   ```javascript
   // Inside populateForm function where you set social media profiles
   if (data.socials && data.socials.service_key) {
       updateServiceVerificationStatus(data.socials.service_key);
   }
   ```

2. In the `updateProfilePreview` function to ensure all verifications are checked:
   ```javascript
   // Inside updateProfilePreview function
   const socials = data.socials || {};
   updateServiceVerificationStatus(socials.service_key || {});
   ```

3. After successful authentication in the callback handler:
   ```javascript
   // Inside handleServiceAuthCallback function after successful auth
   if (event.data.type === 'service_auth_success') {
       // Create a service data object with the profile data
       const serviceData = {
           profile: event.data.username,
           verified: true
       };

       // Update the verification status UI
       updateServiceVerificationStatus(serviceData);

       // Continue with other success handling...
   }
   ```

## Implementation Checklist

When implementing a new OAuth provider, ensure:

1. ✅ **Client UI Elements:**
   - Add UI elements in login.html
   - Create Connect button with unique ID
   - Add verification status display elements
   - Add input field for the service username/identifier

2. ✅ **Client-Side JavaScript:**
   - Implement button click handler
   - Create callback handler function
   - Implement verification status function
   - Update the updateSocialCount() function

3. ✅ **Server-Side PHP:**
   - Create service_oauth.php file
   - Implement OAuth flow (authorization, token exchange, user info)
   - Store wallet address in session
   - Update DNA record with verified service profile
   - Send success/error message back to parent window

4. ✅ **Testing:**
   - Test with valid wallet
   - Test error conditions (empty wallet, auth failure)
   - Verify DNA record is updated
   - Verify social count is incremented

## Example Services to Implement

Future OAuth implementations may include:
- Discord
- GitHub
- Reddit
- LinkedIn
- Instagram
- TikTok

Each will follow this same pattern, with service-specific OAuth details.