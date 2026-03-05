<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit();
}

// Get the request body
$input = file_get_contents('php://input');
if (!$input) {
    http_response_code(400);
    echo json_encode(['error' => 'No request body']);
    exit();
}

// Validate JSON
$requestData = json_decode($input, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit();
}

// Cellframe RPC endpoint
$rpcUrl = 'http://rpc.cellframe.net/connect';

// Create curl handle
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $rpcUrl);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $input);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'Content-Length: ' . strlen($input),
    'User-Agent: CPUNK-IO-RPC-Proxy/1.0'
]);

// Disable SSL verification (since we're using HTTP anyway)
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

// Follow redirects
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_MAXREDIRS, 3);

// Execute request
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);

curl_close($ch);

// Handle curl errors
if ($curlError) {
    http_response_code(502);
    echo json_encode([
        'error' => 'RPC connection failed',
        'details' => $curlError,
        'endpoint' => $rpcUrl
    ]);
    exit();
}

// Handle HTTP errors
if ($httpCode !== 200) {
    http_response_code($httpCode);
    echo json_encode([
        'error' => 'RPC server error',
        'http_code' => $httpCode,
        'response' => $response
    ]);
    exit();
}

// Return the response
if ($response) {
    // Validate that response is valid JSON
    $responseData = json_decode($response, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        echo $response;
    } else {
        http_response_code(502);
        echo json_encode([
            'error' => 'Invalid JSON response from RPC server',
            'raw_response' => $response
        ]);
    }
} else {
    http_response_code(502);
    echo json_encode(['error' => 'Empty response from RPC server']);
}
?>