<?php
/**
 * CPUNK Admin List API Endpoint
 * 
 * Serves the admin list from secure location outside web root
 */

// Set content type to plain text to match original admins.txt behavior
header('Content-Type: text/plain');

// Allow CORS if needed
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Only allow GET requests
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo 'Method not allowed';
    exit();
}

$adminsFile = '/home/deployer/config/admins.txt';

if (!file_exists($adminsFile)) {
    http_response_code(404);
    echo 'Admin list not found';
    exit();
}

// Read and output the admin list
$content = file_get_contents($adminsFile);
if ($content === false) {
    http_response_code(500);
    echo 'Error reading admin list';
    exit();
}

echo $content;
?>