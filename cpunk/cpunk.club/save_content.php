<?php
/**
 * CPUNK Content Editor - Server-side File Save Handler with DNA Authentication
 * 
 * This script handles saving content to text files from the content editor.
 * It includes authentication and debugging features for troubleshooting.
 */

// Disable error display completely - all errors should be logged only
ini_set('display_errors', 0);
error_reporting(0);

// Create log file for detailed debugging
function log_debug($message) {
    try {
        $log_file = 'save_content_debug.log';
        $timestamp = date('Y-m-d H:i:s');
        file_put_contents($log_file, "[$timestamp] $message\n", FILE_APPEND);
    } catch (Exception $e) {
        // Silent fail for logging issues
    }
}

log_debug("Request started");

// Set content type to JSON
header('Content-Type: application/json');

// Allow CORS (if needed)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Log request method
log_debug("Request method: " . $_SERVER['REQUEST_METHOD']);

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    log_debug("Preflight request handled");
    exit();
}

// Verify request method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'message' => 'Method not allowed. Only POST requests are accepted.'
    ]);
    log_debug("Method not allowed: " . $_SERVER['REQUEST_METHOD']);
    exit();
}

// Get raw POST data
$raw_data = file_get_contents('php://input');
log_debug("Raw input data: " . $raw_data);

// Parse JSON data
$data = json_decode($raw_data, true);

// Check for JSON decode errors
if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Invalid JSON data: ' . json_last_error_msg()
    ]);
    log_debug("JSON decode error: " . json_last_error_msg());
    exit();
}

// Log parsed data
log_debug("Parsed data: " . print_r($data, true));

// Simple parameters check - more detailed checking below
if (!is_array($data)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Request data is not a valid JSON object'
    ]);
    log_debug("Invalid data format - not an array");
    exit();
}

// Check for council application submission
if (isset($data['action']) && $data['action'] === 'council_application') {
    // Handle council application
    log_debug("Council application request detected");

    // Verify required parameters for council application
    $required_council_params = ['dna', 'wallet', 'network'];
    $missing_params = [];

    foreach ($required_council_params as $param) {
        if (!isset($data[$param])) {
            $missing_params[] = $param;
        }
    }

    if (!empty($missing_params)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'Missing required parameters for council application: ' . implode(', ', $missing_params)
        ]);
        log_debug("Missing council application parameters: " . implode(', ', $missing_params));
        exit();
    }

    // Extract council application data
    $dna = $data['dna'];
    $wallet = $data['wallet'];
    $network = $data['network'];
    $timestamp = isset($data['timestamp']) ? $data['timestamp'] : date('Y-m-d H:i:s');

    // Create application entry
    $application_entry = json_encode([
        'dna' => $dna,
        'wallet' => $wallet,
        'network' => $network,
        'timestamp' => $timestamp,
        'ip' => $_SERVER['REMOTE_ADDR'],
        'status' => 'pending'
    ], JSON_PRETTY_PRINT);

    // Save to council applications file
    $council_file = 'council_applications.txt';

    try {
        // Append to applications file with a separator
        file_put_contents($council_file, "--- NEW APPLICATION ---\n" . $application_entry . "\n\n", FILE_APPEND);

        // Log application
        log_debug("Council application saved successfully - DNA: $dna, Wallet: $wallet");

        // Return success response
        echo json_encode([
            'success' => true,
            'message' => 'Council application submitted successfully.',
            'timestamp' => $timestamp
        ]);

        log_debug("Council application request completed");
        exit();
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Error saving council application: ' . $e->getMessage()
        ]);
        log_debug("Error saving council application: " . $e->getMessage());
        exit();
    }
}

// For regular content saves, verify each required parameter individually for better debugging
$required_params = ['filename', 'content', 'dna', 'wallet'];
$missing_params = [];

foreach ($required_params as $param) {
    if (!isset($data[$param])) {
        $missing_params[] = $param;
    }
}

if (!empty($missing_params)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Missing required parameters: ' . implode(', ', $missing_params)
    ]);
    log_debug("Missing parameters: " . implode(', ', $missing_params));
    exit();
}

// Define str_starts_with function for PHP < 8.0 compatibility
if (!function_exists('str_starts_with')) {
    function str_starts_with($haystack, $needle) {
        return (string)$needle !== '' && strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}

// Load admins list
function loadAdmins() {
    $adminsFile = 'admins.txt';
    
    if (!file_exists($adminsFile)) {
        log_debug("Admin file not found: $adminsFile");
        return [];
    }
    
    $content = file_get_contents($adminsFile);
    if ($content === false) {
        log_debug("Could not read admin file: $adminsFile");
        return [];
    }
    
    $lines = explode("\n", $content);
    
    $admins = [];
    foreach ($lines as $line) {
        $line = trim($line);
        // Skip empty lines and comments
        if (!empty($line) && !str_starts_with($line, '#')) {
            $admins[] = $line;
        }
    }
    
    log_debug("Loaded admins: " . print_r($admins, true));
    return $admins;
}

// Authenticate user based on DNA
function authenticateUser($dna, $wallet) {
    log_debug("Authenticating user - DNA: $dna, Wallet: $wallet");
    
    // For testing purposes, always return true if dna is "bypass_auth_test"
    if ($dna === "bypass_auth_test") {
        log_debug("Authentication bypassed with test code");
        return true;
    }
    
    $admins = loadAdmins();
    
    // If admins list is empty, authentication fails
    if (empty($admins)) {
        log_debug("Admin list is empty - authentication failed");
        return false;
    }
    
    // Check if the provided DNA is in the admins list (case insensitive)
    foreach ($admins as $admin) {
        if (strcasecmp($dna, $admin) === 0) {
            log_debug("DNA match found: $dna matches admin: $admin");
            return true;
        }
    }
    
    log_debug("No matching admin found for DNA: $dna");
    return false;
}

// Extract data
$filename = $data['filename'];
$content = $data['content'];
$dna = $data['dna'];
$wallet = $data['wallet'];

// Log authentication attempt
log_debug("Authentication attempt - DNA: $dna, Wallet: $wallet");

// Authenticate the request
if (!authenticateUser($dna, $wallet)) {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'message' => 'Authentication failed. Your DNA does not have admin privileges.'
    ]);
    log_debug("Authentication failed");
    exit();
}

// Validate filename
$allowed_files = ['news.txt', 'updates.txt', 'invitation_codes.txt', 'admins.txt', 'content.txt', 'custom.txt']; // Allow specific files to be modified
$allowed_extensions = ['.txt']; // Only allow text files

// Check if filename is in allowed list or has allowed extension
$is_allowed = in_array($filename, $allowed_files);
if (!$is_allowed) {
    // Check file extension
    $file_extension = pathinfo($filename, PATHINFO_EXTENSION);
    $is_allowed_extension = in_array('.' . $file_extension, $allowed_extensions);
    
    if (!$is_allowed_extension) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'Unauthorized file access. Only .txt files are allowed.'
        ]);
        log_debug("Unauthorized file access attempt: $filename");
        exit();
    }
    
    // Additional security: Prevent path traversal
    if (strpos($filename, '../') !== false || strpos($filename, '..\\') !== false) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'Path traversal attempt detected.'
        ]);
        log_debug("Path traversal attempt detected: $filename");
        exit();
    }
}

// Log the edit operation
function logEdit($filename, $dna, $wallet) {
    try {
        $logEntry = date('Y-m-d H:i:s') . " | File: {$filename} | DNA: {$dna} | Wallet: {$wallet}\n";
        file_put_contents('content_edits.log', $logEntry, FILE_APPEND);
        log_debug("Edit logged: $filename by $dna");
    } catch (Exception $e) {
        log_debug("Warning: Failed to log edit: " . $e->getMessage());
        // Continue even if logging fails
    }
}

// Save file
try {
    log_debug("Attempting to save file: $filename");
    
    // Check if file is writable
    if (file_exists($filename) && !is_writable($filename)) {
        throw new Exception("File is not writable: $filename");
    }
    
    $result = file_put_contents($filename, $content);
    
    if ($result !== false) {
        // Log successful edit
        logEdit($filename, $dna, $wallet);
        
        log_debug("File saved successfully: $filename, $result bytes written");
        
        echo json_encode([
            'success' => true,
            'message' => 'File saved successfully.',
            'bytes_written' => $result
        ]);
    } else {
        throw new Exception("Failed to write to file: $filename");
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error: ' . $e->getMessage()
    ]);
    log_debug("Error saving file: " . $e->getMessage());
}

log_debug("Request completed");
