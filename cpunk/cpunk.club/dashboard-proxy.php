<?php
// Dashboard API Proxy for CPUNK - Wraps CLI commands
header('Content-Type: application/json');

// Allow cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle OPTIONS request (preflight)
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Path to cellframe binaries
$CELLFRAME_CLI = '/opt/cellframe-node/bin/cellframe-node-cli';
$CELLFRAME_TOOL = '/opt/cellframe-node/bin/cellframe-node-tool';

// Get request parameters
$method = isset($_GET['method']) ? $_GET['method'] : '';
$params = $_GET;

// Remove method from params
unset($params['method']);

// Log request for debugging
error_log("Dashboard Proxy Request: method=$method, params=" . json_encode($params));

// Handle different methods
switch ($method) {
    case 'CreateWallet':
        handleCreateWallet($params);
        break;
        
    case 'CreateCert':
        handleCreateCert($params);
        break;
        
    case 'GetCertAddress':
        handleGetCertAddress($params);
        break;
        
    case 'RunCommand':
        handleRunCommand($params);
        break;
        
    case 'GetWallets':
        handleGetWallets($params);
        break;
        
    case 'GetDataWallet':
        handleGetDataWallet($params);
        break;
        
    case 'CreateOrderValidator':
        handleCreateOrderValidator($params);
        break;
        
    case 'CreateOrderStaker':
        handleCreateOrderStaker($params);
        break;
        
    default:
        sendError('Unknown method: ' . $method);
        break;
}

/**
 * Create a new wallet
 */
function handleCreateWallet($params) {
    global $CELLFRAME_CLI;
    
    // Required parameters
    if (!isset($params['walletName']) || !isset($params['sign'])) {
        sendError('Missing required parameters: walletName and sign');
        return;
    }
    
    $walletName = escapeshellarg($params['walletName']);
    $signType = escapeshellarg($params['sign']);
    
    // Build command
    $cmd = "$CELLFRAME_CLI wallet new -w $walletName -sign $signType 2>&1";
    
    error_log("Executing: $cmd");
    
    // Execute command
    $output = shell_exec($cmd);
    
    // Parse output
    if (strpos($output, 'successfully created') !== false) {
        echo json_encode([
            'status' => 'ok',
            'data' => [
                'walletName' => $params['walletName'],
                'signType' => $params['sign'],
                'message' => 'Wallet created successfully'
            ]
        ]);
    } else {
        sendError('Failed to create wallet: ' . $output);
    }
}

/**
 * Create a certificate
 */
function handleCreateCert($params) {
    global $CELLFRAME_TOOL;
    
    // Required parameters
    if (!isset($params['certName']) || !isset($params['signType'])) {
        sendError('Missing required parameters: certName and signType');
        return;
    }
    
    $certName = escapeshellarg($params['certName']);
    $signType = escapeshellarg($params['signType']);
    
    // Build command
    $cmd = "$CELLFRAME_TOOL cert create $certName $signType 2>&1";
    
    error_log("Executing: $cmd");
    
    // Execute command
    $output = shell_exec($cmd);
    
    // Parse output
    if (strpos($output, 'created') !== false) {
        echo json_encode([
            'status' => 'ok',
            'data' => [
                'certName' => $params['certName'],
                'signType' => $params['signType'],
                'message' => 'Certificate created successfully'
            ]
        ]);
    } else {
        sendError('Failed to create certificate: ' . $output);
    }
}

/**
 * Get certificate address
 */
function handleGetCertAddress($params) {
    global $CELLFRAME_TOOL;
    
    // Required parameters
    if (!isset($params['certName'])) {
        sendError('Missing required parameter: certName');
        return;
    }
    
    $certName = escapeshellarg($params['certName']);
    
    // Build command
    $cmd = "$CELLFRAME_TOOL cert addr show $certName 2>&1";
    
    error_log("Executing: $cmd");
    
    // Execute command
    $output = trim(shell_exec($cmd));
    
    // Check if we got an address (format: XXXX::XXXX::XXXX::XXXX)
    if (preg_match('/^[0-9A-F]{4}::[0-9A-F]{4}::[0-9A-F]{4}::[0-9A-F]{4}$/i', $output)) {
        echo json_encode([
            'status' => 'ok',
            'data' => [
                'certName' => $params['certName'],
                'address' => $output
            ]
        ]);
    } else {
        sendError('Failed to get certificate address: ' . $output);
    }
}

/**
 * Run arbitrary command
 */
function handleRunCommand($params) {
    global $CELLFRAME_CLI;
    
    // Required parameters
    if (!isset($params['command'])) {
        sendError('Missing required parameter: command');
        return;
    }
    
    // Parse the command to ensure it's safe
    $command = $params['command'];
    
    // Only allow specific commands
    $allowedCommands = ['srv_stake', 'wallet', 'tx_create', 'mempool'];
    $cmdParts = explode(' ', $command);
    $baseCmd = $cmdParts[0];
    
    if (!in_array($baseCmd, $allowedCommands)) {
        sendError('Command not allowed: ' . $baseCmd);
        return;
    }
    
    // Build full command
    $cmd = "$CELLFRAME_CLI $command 2>&1";
    
    error_log("Executing: $cmd");
    
    // Execute command
    $output = shell_exec($cmd);
    
    // Try to detect success/failure
    $success = (strpos($output, 'error') === false && strpos($output, 'Error') === false);
    
    // Extract transaction hash if present
    $tx_hash = null;
    if (preg_match('/0x[a-fA-F0-9]{64}/', $output, $matches)) {
        $tx_hash = $matches[0];
    }
    
    echo json_encode([
        'status' => $success ? 'ok' : 'error',
        'data' => [
            'output' => $output,
            'tx_hash' => $tx_hash,
            'success' => $success
        ]
    ]);
}

/**
 * Get list of wallets
 */
function handleGetWallets($params) {
    global $CELLFRAME_CLI;
    
    // Build command
    $cmd = "$CELLFRAME_CLI wallet list 2>&1";
    
    error_log("Executing: $cmd");
    
    // Execute command
    $output = shell_exec($cmd);
    
    // Parse wallet list
    $wallets = [];
    $lines = explode("\n", $output);
    
    foreach ($lines as $line) {
        $line = trim($line);
        // Skip empty lines and headers
        if (empty($line) || strpos($line, 'wallet') === 0 || strpos($line, '---') !== false) {
            continue;
        }
        
        // Extract wallet name (format varies, but wallet name is usually the first word)
        $parts = preg_split('/\s+/', $line);
        if (!empty($parts[0])) {
            $wallets[] = $parts[0];
        }
    }
    
    echo json_encode([
        'status' => 'ok',
        'data' => $wallets
    ]);
}

/**
 * Get wallet data
 */
function handleGetDataWallet($params) {
    global $CELLFRAME_CLI;
    
    // Required parameters
    if (!isset($params['walletName'])) {
        sendError('Missing required parameter: walletName');
        return;
    }
    
    $walletName = escapeshellarg($params['walletName']);
    $network = isset($params['net']) ? escapeshellarg($params['net']) : 'Backbone';
    
    // Build command
    $cmd = "$CELLFRAME_CLI wallet info -w $walletName -net $network 2>&1";
    
    error_log("Executing: $cmd");
    
    // Execute command
    $output = shell_exec($cmd);
    
    // Parse wallet info
    $data = [];
    $address = null;
    $tokens = [];
    
    // Extract address
    if (preg_match('/addr:\s*([0-9A-F]{4}::[0-9A-F]{4}::[0-9A-F]{4}::[0-9A-F]{4})/i', $output, $matches)) {
        $address = $matches[1];
    }
    
    // Extract token balances
    if (preg_match_all('/(\w+):\s*([\d.]+)\s*(?:coins|datoshi)?/i', $output, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $match) {
            $tokenName = $match[1];
            $balance = $match[2];
            
            // Skip non-token lines
            if (in_array(strtolower($tokenName), ['wallet', 'network', 'addr', 'status'])) {
                continue;
            }
            
            $tokens[] = [
                'tokenName' => $tokenName,
                'balance' => $balance
            ];
        }
    }
    
    $data[] = [
        'network' => str_replace("'", "", $network),
        'address' => $address,
        'tokens' => $tokens
    ];
    
    echo json_encode([
        'status' => 'ok',
        'data' => $data
    ]);
}

/**
 * Create validator order
 */
function handleCreateOrderValidator($params) {
    global $CELLFRAME_CLI;
    
    // Required parameters
    $required = ['net', 'value_min', 'value_max', 'tax', 'cert', 'node_addr'];
    foreach ($required as $param) {
        if (!isset($params[$param])) {
            sendError("Missing required parameter: $param");
            return;
        }
    }
    
    $net = escapeshellarg($params['net']);
    $value_min = escapeshellarg($params['value_min']);
    $value_max = escapeshellarg($params['value_max']);
    $tax = escapeshellarg($params['tax']);
    $cert = escapeshellarg($params['cert']);
    $node_addr = escapeshellarg($params['node_addr']);
    
    // Build command
    $cmd = "$CELLFRAME_CLI srv_stake order create -net $net -cert_node $cert -addr_node $node_addr -value_min $value_min -value_max $value_max -tax $tax 2>&1";
    
    error_log("Executing: $cmd");
    
    // Execute command
    $output = shell_exec($cmd);
    
    // Extract order hash
    $order_hash = null;
    if (preg_match('/order\s+hash[:\s]+([a-fA-F0-9]+)/i', $output, $matches)) {
        $order_hash = $matches[1];
    } elseif (preg_match('/([a-fA-F0-9]{64})/', $output, $matches)) {
        $order_hash = $matches[0];
    }
    
    if ($order_hash) {
        echo json_encode([
            'status' => 'ok',
            'data' => [
                'success' => true,
                'order_hash' => $order_hash,
                'output' => $output
            ]
        ]);
    } else {
        sendError('Failed to create validator order: ' . $output);
    }
}

/**
 * Create staker order (legacy)
 */
function handleCreateOrderStaker($params) {
    global $CELLFRAME_CLI;
    
    // For now, redirect to validator order creation
    handleCreateOrderValidator($params);
}

/**
 * Send error response
 */
function sendError($message) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'error' => $message,
        'errorMsg' => $message
    ]);
    exit();
}
?>