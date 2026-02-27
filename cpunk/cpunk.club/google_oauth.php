<?php
/**
 * Google OAuth Handler for CPUNK
 * This file handles both initiating the OAuth flow and the callback from Google
 */

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Log file for debugging
$logFile = 'google_oauth_log.txt';
function logMsg($message) {
    global $logFile;
    file_put_contents($logFile, date('[Y-m-d H:i:s] ') . $message . PHP_EOL, FILE_APPEND);
}

logMsg('Google OAuth process started');

// Allow cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Google API credentials - hardcoded
$config = require_once('/home/deployer/config/oauth_config.php');
define('CLIENT_ID', $config['google']['client_id']);
define('CLIENT_SECRET', $config['google']['client_secret']);
define('REDIRECT_URI', 'https://cpunk.club/google_oauth.php');

logMsg('Using hardcoded credentials');
logMsg('CLIENT_ID: ' . CLIENT_ID);
logMsg('REDIRECT_URI: ' . REDIRECT_URI);

// Update redirect to use the current script instead of REDIRECT_URI from credentials file
define('OAUTH_CALLBACK', 'https://' . $_SERVER['HTTP_HOST'] . '/google_oauth.php');

// DNA API endpoint - use absolute URL
define('DNA_API_URL', 'https://' . $_SERVER['HTTP_HOST'] . '/dna-proxy.php');

// Initialize session to store OAuth tokens
session_start();

// Handle the initial OAuth request
if (isset($_GET['request']) && $_GET['request'] == 'auth') {
    logMsg('Starting auth request. Wallet: ' . ($_GET['wallet'] ?? 'not provided'));
    
    // Store wallet address in session
    if (isset($_GET['wallet'])) {
        $_SESSION['wallet_address'] = $_GET['wallet'];
        logMsg('Stored wallet address in session: ' . $_GET['wallet']);
    }
    
    // Generate state parameter to prevent CSRF
    $state = bin2hex(random_bytes(16));
    $_SESSION['oauth_state'] = $state;
    
    // Build authorization URL
    $authUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
    $params = [
        'client_id' => CLIENT_ID,
        'redirect_uri' => OAUTH_CALLBACK,
        'response_type' => 'code',
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
        'state' => $state,
        'prompt' => 'select_account',
        'access_type' => 'offline'
    ];
    
    $authUrl .= '?' . http_build_query($params);
    
    logMsg('Redirecting to Google auth URL: ' . $authUrl);
    header('Location: ' . $authUrl);
    exit;
}

// Handle the callback from Google
if (isset($_GET['code']) && isset($_GET['state'])) {
    logMsg('Received callback from Google. State: ' . $_GET['state']);
    
    // Verify state parameter to prevent CSRF
    if (!isset($_SESSION['oauth_state']) || $_SESSION['oauth_state'] !== $_GET['state']) {
        logMsg('State mismatch. Session: ' . ($_SESSION['oauth_state'] ?? 'not set') . ', Callback: ' . $_GET['state']);
        echo "<script>
            window.opener.postMessage({
                type: 'google_auth_error',
                error: 'State parameter mismatch'
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Exchange code for access token
    $tokenUrl = 'https://oauth2.googleapis.com/token';
    $postData = [
        'code' => $_GET['code'],
        'client_id' => CLIENT_ID,
        'client_secret' => CLIENT_SECRET,
        'redirect_uri' => OAUTH_CALLBACK,
        'grant_type' => 'authorization_code'
    ];
    
    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/x-www-form-urlencoded'
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    logMsg('Token response code: ' . $httpCode);
    logMsg('Token response: ' . $response);
    
    if ($httpCode != 200) {
        logMsg('Failed to get access token. Response: ' . $response);
        echo "<script>
            window.opener.postMessage({
                type: 'google_auth_error',
                error: 'Failed to get access token',
                response: " . json_encode($response) . "
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Parse token response
    $tokenData = json_decode($response, true);
    
    if (!isset($tokenData['access_token'])) {
        logMsg('Invalid token response format. Response: ' . $response);
        echo "<script>
            window.opener.postMessage({
                type: 'google_auth_error',
                error: 'Invalid token response',
                response: " . json_encode($response) . "
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    $accessToken = $tokenData['access_token'];
    
    // Get user info with access token
    $userInfoUrl = 'https://www.googleapis.com/oauth2/v2/userinfo';
    $ch = curl_init($userInfoUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $accessToken
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    logMsg('User info response code: ' . $httpCode);
    logMsg('User info response: ' . $response);
    
    if ($httpCode != 200) {
        logMsg('Failed to get user info. Response: ' . $response);
        echo "<script>
            window.opener.postMessage({
                type: 'google_auth_error',
                error: 'Failed to get user info',
                response: " . json_encode($response) . "
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Parse user info
    $userInfo = json_decode($response, true);
    
    if (!isset($userInfo['email'])) {
        logMsg('Invalid user info format. Response: ' . $response);
        echo "<script>
            window.opener.postMessage({
                type: 'google_auth_error',
                error: 'Invalid user info',
                response: " . json_encode($response) . "
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    $googleEmail = $userInfo['email'];
    $googleName = $userInfo['name'] ?? '';
    
    logMsg('Google email: ' . $googleEmail);
    
    // Get wallet address from session or query parameter
    $walletAddress = '';
    if (isset($_GET['wallet']) && !empty($_GET['wallet'])) {
        $walletAddress = $_GET['wallet'];
        logMsg('Got wallet address from query param: ' . $walletAddress);
        // Also store in session for future use
        $_SESSION['wallet_address'] = $walletAddress;
    } elseif (isset($_SESSION['wallet_address']) && !empty($_SESSION['wallet_address'])) {
        $walletAddress = $_SESSION['wallet_address'];
        logMsg('Got wallet address from session: ' . $walletAddress);
    }

    // If still no wallet address but we have a GUID/nickname, try to look it up
    if (empty($walletAddress) && isset($_SESSION['guid'])) {
        logMsg('No wallet address found, but GUID is available. Could look up wallet from DNA API using GUID: ' . $_SESSION['guid']);
        // This would need a DNA API call to get the wallet for a GUID
    }
    
    // If we have a wallet address, update DNA
    $result = [];
    if (!empty($walletAddress)) {
        logMsg('Updating DNA with Google email: ' . $googleEmail . ' for wallet: ' . $walletAddress);
        $result = updateDnaGoogle($walletAddress, $googleEmail);
        logMsg('DNA update result: ' . json_encode($result));
    } else {
        logMsg('No wallet address available for DNA update');
    }
    
    // Send result back to opener window and close
    echo "<script>
        window.opener.postMessage({
            type: 'google_auth_success',
            email: " . json_encode($googleEmail) . ",
            name: " . json_encode($googleName) . ",
            result: " . json_encode($result) . "
        }, '*');
        window.close();
    </script>";
    exit;
}

/**
 * Update the user's DNA record with their Google email
 */
function updateDnaGoogle($walletAddress, $googleEmail) {
    global $logFile;
    
    logMsg('Starting DNA update for Google email: ' . $googleEmail);
    
    // Prepare data for update
    $updateData = [
        'action' => 'update',
        'wallet' => $walletAddress,
        'socials' => [
            'google' => [
                'profile' => $googleEmail,
                'verified' => true
            ]
        ]
    ];
    
    $postData = json_encode($updateData);
    logMsg('DNA update data: ' . $postData);
    logMsg('DNA API URL: ' . DNA_API_URL);
    
    // Make POST request to update DNA
    $ch = curl_init(DNA_API_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Content-Length: ' . strlen($postData)
    ]);
    
    // Add verbose debugging
    $verbose = fopen('php://temp', 'w+');
    curl_setopt($ch, CURLOPT_VERBOSE, true);
    curl_setopt($ch, CURLOPT_STDERR, $verbose);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    // Get verbose debug information
    rewind($verbose);
    $verboseLog = stream_get_contents($verbose);
    logMsg('CURL Verbose log: ' . $verboseLog);
    
    // Check for curl errors
    if (curl_errno($ch)) {
        $error = curl_error($ch);
        logMsg('CURL Error: ' . $error);
        curl_close($ch);
        return ['error' => 'CURL error: ' . $error];
    }
    
    curl_close($ch);
    
    logMsg('DNA API response code: ' . $httpCode);
    logMsg('DNA API response: ' . $response);
    
    // Try to parse response
    $result = [];
    try {
        $result = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            logMsg('JSON Parse Error: ' . json_last_error_msg());
            $result = ['error' => 'Failed to parse JSON response', 'response' => $response];
        }
    } catch (Exception $e) {
        logMsg('Exception parsing response: ' . $e->getMessage());
        $result = ['error' => 'Exception: ' . $e->getMessage(), 'response' => $response];
    }
    
    if (empty($result)) {
        // If response is empty or couldn't be parsed, but we got a success HTTP code
        if ($httpCode >= 200 && $httpCode < 300) {
            $result = ['success' => true, 'message' => 'DNA updated successfully'];
            logMsg('DNA update appears successful based on HTTP code');
        } else {
            $result = ['error' => 'Empty response with HTTP code: ' . $httpCode, 'response' => $response];
            logMsg('DNA update failed with HTTP code: ' . $httpCode);
        }
    }
    
    return $result;
}

// Default response for direct access
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['request']) && !isset($_GET['code'])) {
    // Store wallet address in session if provided
    if (isset($_GET['wallet'])) {
        $_SESSION['wallet_address'] = $_GET['wallet'];
        logMsg('Stored wallet address for later: ' . $_GET['wallet']);
    }
    
    // Display a simple page for debugging
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>CPUNK Google OAuth</title>
        <style>
            body {
                font-family: 'Arial', sans-serif;
                background-color: #0a0a0a;
                color: #ffffff;
                margin: 0;
                padding: 20px;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                flex-direction: column;
            }
            .container {
                background-color: #2b1816;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(255, 255, 255, 0.2);
                width: 100%;
                max-width: 600px;
                text-align: center;
            }
            h1 {
                color: #f97834;
                margin-bottom: 20px;
            }
            p {
                margin-bottom: 20px;
                line-height: 1.6;
            }
            .button {
                background-color: #f97834;
                color: #ffffff;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                cursor: pointer;
                font-family: 'Courier New', monospace;
                font-size: 1em;
                text-decoration: none;
                display: inline-block;
                margin-top: 20px;
                transition: all 0.3s ease;
            }
            .button:hover {
                background-color: #ff9055;
                box-shadow: 0 0 15px #f97834;
            }
            
            .wallet-info {
                margin-top: 20px;
                padding: 10px;
                background-color: rgba(249, 120, 52, 0.1);
                border-radius: 5px;
                font-family: 'Courier New', monospace;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>CPUNK Google OAuth</h1>
            <p>This page handles Google authentication for CPUNK users. You shouldn't see this page directly.</p>
            <p>If you're trying to connect your Google account, please do so from the User Settings page.</p>
            
            <?php if (isset($_SESSION['wallet_address'])): ?>
            <div class="wallet-info">
                Wallet address detected: <?php echo htmlspecialchars($_SESSION['wallet_address']); ?>
            </div>
            <?php endif; ?>
            
            <a href="google_oauth.php?request=auth<?php echo isset($_SESSION['wallet_address']) ? '&wallet='.urlencode($_SESSION['wallet_address']) : ''; ?>" class="button">Connect Google (Debug)</a>
        </div>
    </body>
    </html>
    <?php
}
?>