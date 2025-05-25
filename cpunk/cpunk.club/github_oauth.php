<?php
/**
 * GitHub OAuth Handler for CPUNK
 * This file handles both initiating the OAuth flow and the callback from GitHub
 */

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Log file for debugging
$logFile = 'github_oauth_log.txt';
function logMsg($message) {
    global $logFile;
    file_put_contents($logFile, date('[Y-m-d H:i:s] ') . $message . PHP_EOL, FILE_APPEND);
}

logMsg('GitHub OAuth process started');

// Allow cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// GitHub API credentials
$config = require_once('/home/deployer/config/oauth_config.php');
define('CLIENT_ID', $config['github']['client_id']);
define('CLIENT_SECRET', $config['github']['client_secret']);
define('REDIRECT_URI', 'https://cpunk.club/github_oauth.php');

logMsg('Using credentials for GitHub OAuth');
logMsg('CLIENT_ID: ' . CLIENT_ID);
logMsg('REDIRECT_URI: ' . REDIRECT_URI);

// Update redirect to use the current script
define('OAUTH_CALLBACK', 'https://' . $_SERVER['HTTP_HOST'] . '/github_oauth.php');

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
    
    // Build authorization URL for GitHub OAuth 2.0
    $authUrl = 'https://github.com/login/oauth/authorize';
    $params = [
        'client_id' => CLIENT_ID,
        'redirect_uri' => OAUTH_CALLBACK,
        'state' => $state,
        'scope' => 'read:user user:email'
    ];
    
    $authUrl .= '?' . http_build_query($params);
    
    logMsg('Redirecting to GitHub auth URL: ' . $authUrl);
    header('Location: ' . $authUrl);
    exit;
}

// Handle errors returned from GitHub
if (isset($_GET['error'])) {
    $error = $_GET['error'];
    $errorDescription = isset($_GET['error_description']) ? $_GET['error_description'] : 'No description provided';
    $state = isset($_GET['state']) ? $_GET['state'] : 'No state provided';

    logMsg('GitHub returned an error: ' . $error . ' - ' . $errorDescription);

    echo "<script>
        window.opener.postMessage({
            type: 'github_auth_error',
            error: " . json_encode($error) . ",
            error_description: " . json_encode($errorDescription) . ",
            state: " . json_encode($state) . "
        }, '*');
        window.close();
    </script>";
    exit;
}

// Handle the callback from GitHub
if (isset($_GET['code']) && isset($_GET['state'])) {
    logMsg('Received callback from GitHub. State: ' . $_GET['state']);
    
    // Verify state parameter to prevent CSRF
    if (!isset($_SESSION['oauth_state']) || $_SESSION['oauth_state'] !== $_GET['state']) {
        logMsg('State mismatch. Session: ' . ($_SESSION['oauth_state'] ?? 'not set') . ', Callback: ' . $_GET['state']);
        echo "<script>
            window.opener.postMessage({
                type: 'github_auth_error',
                error: 'State parameter mismatch'
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Exchange code for access token
    $tokenUrl = 'https://github.com/login/oauth/access_token';
    $postData = [
        'client_id' => CLIENT_ID,
        'client_secret' => CLIENT_SECRET,
        'code' => $_GET['code'],
        'redirect_uri' => OAUTH_CALLBACK
    ];
    
    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/json',
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
                type: 'github_auth_error',
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
                type: 'github_auth_error',
                error: 'Invalid token response',
                response: " . json_encode($response) . "
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    $accessToken = $tokenData['access_token'];
    
    // Get user profile information with access token
    $profileUrl = 'https://api.github.com/user';
    $ch = curl_init($profileUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: token ' . $accessToken,
        'User-Agent: CPUNK-OAuth-App',
        'Accept: application/json'
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    logMsg('Profile response code: ' . $httpCode);
    logMsg('Profile response: ' . $response);
    
    if ($httpCode != 200) {
        logMsg('Failed to get profile info. Response: ' . $response);
        echo "<script>
            window.opener.postMessage({
                type: 'github_auth_error',
                error: 'Failed to get profile info from GitHub API',
                response: " . json_encode($response) . "
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Parse profile info
    $profileInfo = json_decode($response, true);
    
    // Log the complete profile information to see all available fields
    logMsg('Complete GitHub profile response: ' . json_encode($profileInfo, JSON_PRETTY_PRINT));
    
    if (!isset($profileInfo['id'])) {
        logMsg('Invalid profile info format. Response: ' . $response);
        echo "<script>
            window.opener.postMessage({
                type: 'github_auth_error',
                error: 'GitHub ID not found in response',
                response: " . json_encode($response) . "
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Get GitHub username as the primary identifier
    $githubUsername = $profileInfo['login'];
    
    // Get name for display purposes
    $githubName = isset($profileInfo['name']) ? $profileInfo['name'] : '';
    
    logMsg('GitHub Username: ' . $githubUsername);
    if ($githubName) {
        logMsg('GitHub Name: ' . $githubName);
    }
    
    // Get email from GitHub if available and user has allowed email access
    $userEmail = '';
    if (isset($profileInfo['email']) && !empty($profileInfo['email'])) {
        $userEmail = $profileInfo['email'];
    } else {
        // Try getting email from the email endpoint
        $emailUrl = 'https://api.github.com/user/emails';
        $ch = curl_init($emailUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: token ' . $accessToken,
            'User-Agent: CPUNK-OAuth-App',
            'Accept: application/json'
        ]);
        
        $emailResponse = curl_exec($ch);
        $emailHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        logMsg('Email response code: ' . $emailHttpCode);
        logMsg('Email response: ' . $emailResponse);
        
        if ($emailHttpCode == 200) {
            $emails = json_decode($emailResponse, true);
            if (is_array($emails) && !empty($emails)) {
                // Find primary email
                foreach ($emails as $email) {
                    if (isset($email['primary']) && $email['primary'] && isset($email['email'])) {
                        $userEmail = $email['email'];
                        break;
                    }
                }
                
                // If no primary email, use the first verified email
                if (empty($userEmail)) {
                    foreach ($emails as $email) {
                        if (isset($email['verified']) && $email['verified'] && isset($email['email'])) {
                            $userEmail = $email['email'];
                            break;
                        }
                    }
                }
                
                // As a last resort, use the first email
                if (empty($userEmail) && isset($emails[0]['email'])) {
                    $userEmail = $emails[0]['email'];
                }
                
                logMsg('Found GitHub email: ' . $userEmail);
            }
        }
    }
    
    // Get wallet address from session or query parameter
    $walletAddress = '';
    if (isset($_GET['wallet']) && !empty($_GET['wallet'])) {
        $walletAddress = $_GET['wallet'];
        logMsg('Got wallet address from query param: ' . $walletAddress);
    } elseif (isset($_SESSION['wallet_address']) && !empty($_SESSION['wallet_address'])) {
        $walletAddress = $_SESSION['wallet_address'];
        logMsg('Got wallet address from session: ' . $walletAddress);
    }
    
    if (empty($walletAddress)) {
        logMsg('No wallet address provided');
        echo "<script>
            window.opener.postMessage({
                type: 'github_auth_error',
                error: 'Wallet address is missing'
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Update DNA record
    logMsg('Updating DNA record for wallet: ' . $walletAddress . ' with GitHub username: ' . $githubUsername);
    
    $updateData = [
        'action' => 'update',
        'wallet' => $walletAddress,
        'socials' => [
            'github' => [
                'profile' => $githubUsername,
                'verified' => true
            ]
        ]
    ];
    
    // Add name if available
    if ($githubName) {
        $updateData['socials']['github']['name'] = $githubName;
    }
    
    // Add email if available
    if ($userEmail) {
        $updateData['socials']['github']['email'] = $userEmail;
    }
    
    $postData = json_encode($updateData);
    
    $ch = curl_init(DNA_API_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    logMsg('DNA API response code: ' . $httpCode);
    logMsg('DNA API response: ' . $response);
    
    if ($httpCode < 200 || $httpCode >= 300) {
        echo "<script>
            window.opener.postMessage({
                type: 'github_auth_error',
                error: 'Failed to update DNA record',
                response: " . json_encode($response) . "
            }, '*');
            window.close();
        </script>";
        exit;
    }
    
    // Send success message back to opener - simple version
    echo "<script>
        window.opener.postMessage({
            type: 'github_auth_success',
            username: " . json_encode($githubUsername) . ",
            name: " . json_encode($githubName) . "
        }, '*');
        window.close();
    </script>";
    exit;
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
        <title>CPUNK GitHub OAuth</title>
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
                background-color: #24292e; /* GitHub dark */
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
                background-color: #3c4146;
                box-shadow: 0 0 15px #24292e;
            }
            
            .wallet-info {
                margin-top: 20px;
                padding: 10px;
                background-color: rgba(36, 41, 46, 0.1);
                border-radius: 5px;
                font-family: 'Courier New', monospace;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>CPUNK GitHub OAuth</h1>
            <p>This page handles GitHub authentication for CPUNK users. You shouldn't see this page directly.</p>
            <p>If you're trying to connect your GitHub account, please do so from the User Settings page.</p>
            
            <?php if (isset($_SESSION['wallet_address'])): ?>
            <div class="wallet-info">
                Wallet address detected: <?php echo htmlspecialchars($_SESSION['wallet_address']); ?>
            </div>
            <?php endif; ?>
            
            <a href="github_oauth.php?request=auth<?php echo isset($_SESSION['wallet_address']) ? '&wallet='.urlencode($_SESSION['wallet_address']) : ''; ?>" class="button">Connect GitHub (Debug)</a>
        </div>
    </body>
    </html>
    <?php
}
?>