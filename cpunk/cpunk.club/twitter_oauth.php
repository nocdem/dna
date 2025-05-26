<?php
/**
 * Twitter OAuth 2.0 Callback Handler for CPUNK
 * This file handles the OAuth 2.0 callback from Twitter and updates the user's DNA record
 */

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Log file for debugging
$logFile = 'twitter_oauth_log.txt';
function logMsg($message) {
    global $logFile;
    file_put_contents($logFile, date('[Y-m-d H:i:s] ') . $message . PHP_EOL, FILE_APPEND);
}

logMsg('Twitter OAuth 2.0 process started');

// Allow cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Twitter API credentials
$configFile = '/home/deployer/config/oauth_config.php';
if (!file_exists($configFile)) {
    logMsg('OAuth configuration file not found at: ' . $configFile);
    die('<h1>OAuth Configuration Error</h1><p>The OAuth configuration is not properly set up. Please contact the administrator.</p><p>Configuration file missing: ' . htmlspecialchars($configFile) . '</p>');
}

$config = require_once($configFile);

if (!isset($config['twitter']['client_id']) || !isset($config['twitter']['client_secret'])) {
    logMsg('Twitter OAuth credentials not found in configuration');
    die('<h1>OAuth Configuration Error</h1><p>Twitter OAuth credentials are not configured. Please contact the administrator.</p>');
}

define('CLIENT_ID', $config['twitter']['client_id']);
define('CLIENT_SECRET', $config['twitter']['client_secret']);
define('REDIRECT_URI', 'https://' . $_SERVER['HTTP_HOST'] . '/twitter_oauth.php');

session_start();

// Generate random state for CSRF protection
function generateState() {
    return bin2hex(random_bytes(16));
}

// Handle the initial authorization request
if (isset($_GET['auth']) && $_GET['auth'] === 'start') {
    logMsg('Starting Twitter OAuth 2.0 authorization');
    
    // Store wallet address in session
    if (isset($_GET['wallet'])) {
        $_SESSION['wallet_address'] = $_GET['wallet'];
        logMsg('Stored wallet address in session: ' . $_GET['wallet']);
    }
    
    // Generate and store state
    $state = generateState();
    $_SESSION['twitter_oauth_state'] = $state;
    
    // Twitter OAuth 2.0 authorization URL
    $authUrl = 'https://twitter.com/i/oauth2/authorize?' . http_build_query([
        'response_type' => 'code',
        'client_id' => CLIENT_ID,
        'redirect_uri' => REDIRECT_URI,
        'scope' => 'users.read tweet.read',
        'state' => $state,
        'code_challenge' => 'challenge',
        'code_challenge_method' => 'plain'
    ]);
    
    logMsg('Redirecting to: ' . $authUrl);
    header('Location: ' . $authUrl);
    exit;
}

// Handle the callback from Twitter
if (isset($_GET['code'])) {
    logMsg('Received callback from Twitter with code');
    
    // Verify state to prevent CSRF
    if (!isset($_GET['state']) || !isset($_SESSION['twitter_oauth_state']) || 
        $_GET['state'] !== $_SESSION['twitter_oauth_state']) {
        logMsg('State mismatch - possible CSRF attack');
        echo "<script>
            window.opener.postMessage({
                type: 'twitter_auth_error',
                error: 'State mismatch'
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Exchange code for access token
    $tokenUrl = 'https://api.twitter.com/2/oauth2/token';
    
    $postData = [
        'grant_type' => 'authorization_code',
        'code' => $_GET['code'],
        'redirect_uri' => REDIRECT_URI,
        'code_verifier' => 'challenge'
    ];
    
    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/x-www-form-urlencoded',
        'Authorization: Basic ' . base64_encode(CLIENT_ID . ':' . CLIENT_SECRET)
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    logMsg('Token response code: ' . $httpCode);
    logMsg('Token response: ' . $response);
    
    if ($httpCode != 200) {
        echo "<script>
            window.opener.postMessage({
                type: 'twitter_auth_error',
                error: 'Failed to get access token'
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    $tokenData = json_decode($response, true);
    $accessToken = $tokenData['access_token'];
    
    // Get user info
    $userUrl = 'https://api.twitter.com/2/users/me';
    
    $ch = curl_init($userUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $accessToken
    ]);
    
    $userResponse = curl_exec($ch);
    $userHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    logMsg('User info response code: ' . $userHttpCode);
    logMsg('User info response: ' . $userResponse);
    
    if ($userHttpCode == 200) {
        $userData = json_decode($userResponse, true);
        $username = $userData['data']['username'];
        
        logMsg('Successfully authenticated user: ' . $username);
        
        // Get wallet address from session or query parameter
        $walletAddress = '';
        if (isset($_GET['wallet']) && !empty($_GET['wallet'])) {
            $walletAddress = $_GET['wallet'];
            logMsg('Got wallet address from query param: ' . $walletAddress);
        } elseif (isset($_SESSION['wallet_address']) && !empty($_SESSION['wallet_address'])) {
            $walletAddress = $_SESSION['wallet_address'];
            logMsg('Got wallet address from session: ' . $walletAddress);
        }
        
        // Update DNA record if we have a wallet address
        $result = [];
        if (!empty($walletAddress)) {
            logMsg('Updating DNA with Twitter username: ' . $username . ' for wallet: ' . $walletAddress);
            $result = updateDnaTwitter($walletAddress, $username);
            logMsg('DNA update result: ' . json_encode($result));
        } else {
            logMsg('No wallet address available for DNA update');
        }
        
        // Send success message to parent window
        echo "<script>
            window.opener.postMessage({
                type: 'twitter_auth_success',
                username: '" . addslashes($username) . "',
                result: " . json_encode($result) . "
            }, '*');
            window.close();
        </script>";
    } else {
        echo "<script>
            window.opener.postMessage({
                type: 'twitter_auth_error',
                error: 'Failed to get user info'
            }, '*');
            window.close();
        </script>";
    }
    exit;
}

// Handle errors
if (isset($_GET['error'])) {
    logMsg('Twitter returned error: ' . $_GET['error']);
    echo "<script>
        window.opener.postMessage({
            type: 'twitter_auth_error',
            error: '" . addslashes($_GET['error_description'] ?? $_GET['error']) . "'
        }, '*');
        window.close();
    </script>";
    exit;
}

/**
 * Update the user's DNA record with their Twitter username
 */
function updateDnaTwitter($walletAddress, $twitterUsername) {
    global $logFile;
    
    logMsg('Starting DNA update for Twitter username: ' . $twitterUsername);
    
    // DNA API endpoint
    $dnaApiUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/dna-proxy.php';
    
    // Prepare data for update
    $updateData = [
        'action' => 'update',
        'wallet' => $walletAddress,
        'socials' => [
            'x' => [
                'profile' => $twitterUsername,
                'verified' => true
            ]
        ]
    ];
    
    $postData = json_encode($updateData);
    logMsg('DNA update data: ' . $postData);
    logMsg('DNA API URL: ' . $dnaApiUrl);
    
    // Make POST request to update DNA
    $ch = curl_init($dnaApiUrl);
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

// If no action specified, show error
echo json_encode(['error' => 'No action specified']);
?>