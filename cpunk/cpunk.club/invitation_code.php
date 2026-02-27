<?php
/**
 * CPUNK Mainnet Birthday Bash - Invitation Code Handler
 * Simple text file based implementation
 */

// Allow cross-origin requests if needed
header('Content-Type: application/json');

// Disable error display in the output
ini_set('display_errors', 0);
error_reporting(E_ALL);

// File paths
$VALID_CODES_FILE = 'invitation_codes.txt';
$CODE_ATTENDEES_FILE = 'code_attendees.txt';
$LOGS_FILE = 'invitation_logs.txt';

// Helper function to log activities
function log_activity($message, $data = []) {
    global $LOGS_FILE;
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[{$timestamp}] {$message} " . json_encode($data) . "\n";
    
    // Append to log file
    file_put_contents($LOGS_FILE, $log_entry, FILE_APPEND);
}

// Load valid codes from text file (one code per line)
function load_valid_codes() {
    global $VALID_CODES_FILE;
    
    if (!file_exists($VALID_CODES_FILE)) {
        return [];
    }
    
    // Read codes from file
    $codes_content = file_get_contents($VALID_CODES_FILE);
    $codes = array_filter(explode("\n", $codes_content)); // Split by newline and remove empty lines
    
    return $codes;
}

// Save a new attendee who used an invitation code
function save_code_attendee($dna, $wallet, $code) {
    global $CODE_ATTENDEES_FILE;

    // Format: DNA|CODE|TIMESTAMP|WALLET
    $entry = $dna . '|' . $code . '|' . date('Y-m-d H:i:s') . '|' . $wallet . "\n";

    // Log before attempting write
    error_log("Attempting to write to $CODE_ATTENDEES_FILE: $entry");
    
    // Make sure the file exists and is writable
    if (!file_exists($CODE_ATTENDEES_FILE)) {
        touch($CODE_ATTENDEES_FILE);
        chmod($CODE_ATTENDEES_FILE, 0666); // Make it writable
    }

    // Append to file
    $result = file_put_contents($CODE_ATTENDEES_FILE, $entry, FILE_APPEND);

    // Check if write was successful
    if ($result === false) {
        error_log("ERROR: Failed to write to $CODE_ATTENDEES_FILE");
        // Try to diagnose the issue
        error_log("File exists: " . (file_exists($CODE_ATTENDEES_FILE) ? 'Yes' : 'No'));
        error_log("File writeable: " . (is_writable($CODE_ATTENDEES_FILE) ? 'Yes' : 'No'));
        throw new Exception("Failed to save reservation data: Could not write to file");
    } else {
        error_log("Successfully wrote $result bytes to $CODE_ATTENDEES_FILE");
    }
}

// Check if wallet already has a reservation
function check_wallet_reservation($wallet) {
    global $CODE_ATTENDEES_FILE;
    
    // Check code_attendees.txt
    if (file_exists($CODE_ATTENDEES_FILE)) {
        $attendees_content = file_get_contents($CODE_ATTENDEES_FILE);
        $attendees = explode("\n", $attendees_content);
        
        foreach ($attendees as $attendee) {
            if (empty($attendee)) continue;
            
            $parts = explode('|', $attendee);
            if (count($parts) >= 4 && $parts[3] === $wallet) {
                return true;
            }
        }
    }
    
    // Check party_list.txt
    if (file_exists('party_list.txt')) {
        $party_content = file_get_contents('party_list.txt');
        $party_members = explode("\n", $party_content);
        
        foreach ($party_members as $member) {
            if (empty($member)) continue;
            
            $parts = explode('|', $member);
            if (count($parts) >= 4 && $parts[3] === $wallet) {
                return true;
            }
        }
    }
    
    return false;
}

// Check if DNA already has a reservation
function check_dna_reservation($dna) {
    global $CODE_ATTENDEES_FILE;
    
    // Check code_attendees.txt
    if (file_exists($CODE_ATTENDEES_FILE)) {
        $attendees_content = file_get_contents($CODE_ATTENDEES_FILE);
        $attendees = explode("\n", $attendees_content);
        
        foreach ($attendees as $attendee) {
            if (empty($attendee)) continue;
            
            $parts = explode('|', $attendee);
            if (count($parts) >= 1 && $parts[0] === $dna) {
                return true;
            }
        }
    }
    
    // Check party_list.txt
    if (file_exists('party_list.txt')) {
        $party_content = file_get_contents('party_list.txt');
        $party_members = explode("\n", $party_content);
        
        foreach ($party_members as $member) {
            if (empty($member)) continue;
            
            $parts = explode('|', $member);
            if (count($parts) >= 1 && $parts[0] === $dna) {
                return true;
            }
        }
    }
    
    return false;
}

// Get all attendees who registered with codes
function get_code_attendees() {
    global $CODE_ATTENDEES_FILE;
    $attendees = [];
    
    if (!file_exists($CODE_ATTENDEES_FILE)) {
        return $attendees;
    }
    
    $attendees_content = file_get_contents($CODE_ATTENDEES_FILE);
    $attendee_lines = explode("\n", $attendees_content);
    
    foreach ($attendee_lines as $line) {
        if (empty($line)) continue;
        
        $parts = explode('|', $line);
        if (count($parts) >= 3) {
            $attendees[] = [
                'nickname' => $parts[0],
                'status' => 'Confirmed',
                'type' => 'vip'
            ];
        }
    }
    
    return $attendees;
}

// Remove code from valid codes file after use
function remove_code($code) {
    global $VALID_CODES_FILE;

    error_log("Attempting to remove code '$code' from $VALID_CODES_FILE");

    $codes = load_valid_codes();
    error_log("Loaded " . count($codes) . " codes: " . implode(", ", $codes));

    $key = array_search($code, $codes);
    error_log("Search result for '$code': " . ($key !== false ? "Found at position $key" : "Not found"));

    if ($key !== false) {
        unset($codes[$key]);

        $newContent = implode("\n", $codes) . (empty($codes) ? "" : "\n");
        error_log("New content for $VALID_CODES_FILE: " . str_replace("\n", "\\n", $newContent));

        $result = file_put_contents($VALID_CODES_FILE, $newContent);

        if ($result === false) {
            error_log("ERROR: Failed to write to $VALID_CODES_FILE");
            error_log("File exists: " . (file_exists($VALID_CODES_FILE) ? 'Yes' : 'No'));
            error_log("File writeable: " . (is_writable($VALID_CODES_FILE) ? 'Yes' : 'No'));
            throw new Exception("Failed to update invitation codes: Could not write to file");
        } else {
            error_log("Successfully wrote $result bytes to $VALID_CODES_FILE");
        }
    }
}

// Get the action from request
$action = $_POST['action'] ?? $_GET['action'] ?? '';

// Process based on the action
switch ($action) {
    case 'validate':
        // Get the code from request
        $code = $_POST['code'] ?? $_GET['code'] ?? '';
        $code = trim($code);
        
        // Load valid codes
        $valid_codes = load_valid_codes();
        
        // Check if code is valid
        if (!in_array($code, $valid_codes)) {
            log_activity('Invalid code attempted', ['code' => $code]);
            echo json_encode(['valid' => false, 'message' => 'Invalid invitation code']);
            exit;
        }
        
        // Return success if code is valid
        echo json_encode([
            'valid' => true, 
            'message' => 'Valid invitation code',
            'code_type' => 'vip',
            'description' => 'VIP Guest'
        ]);
        break;
        
    case 'redeem':
        // Get parameters from request
        $code = $_POST['code'] ?? $_GET['code'] ?? '';
        $code = trim($code);
        $dna = $_POST['dna'] ?? $_GET['dna'] ?? '';
        $wallet = $_POST['wallet'] ?? $_GET['wallet'] ?? '';
        
        // Validate inputs
        if (empty($code) || empty($dna) || empty($wallet)) {
            log_activity('Missing parameters', ['code' => $code, 'dna' => $dna, 'wallet' => $wallet]);
            echo json_encode(['success' => false, 'message' => 'Missing required parameters']);
            exit;
        }
        
        // Load valid codes
        $valid_codes = load_valid_codes();
        
        // Check if code is valid
        if (!in_array($code, $valid_codes)) {
            log_activity('Invalid code redemption attempt', ['code' => $code, 'dna' => $dna]);
            echo json_encode(['success' => false, 'message' => 'Invalid invitation code']);
            exit;
        }
        
        // Check if wallet already has a reservation
        if (check_wallet_reservation($wallet)) {
            log_activity('Wallet already has reservation', ['wallet' => $wallet, 'dna' => $dna]);
            echo json_encode(['success' => false, 'message' => 'This wallet already has a reservation']);
            exit;
        }
        
        // Check if DNA already has a reservation
        if (check_dna_reservation($dna)) {
            log_activity('DNA already has reservation', ['dna' => $dna]);
            echo json_encode(['success' => false, 'message' => 'This DNA already has a reservation']);
            exit;
        }
        
        // Process reservation
        try {
            // Save the reservation
            save_code_attendee($dna, $wallet, $code);
            
            // Remove the code from valid codes
            remove_code($code);
            
            log_activity('Successful code redemption', [
                'code' => $code, 
                'dna' => $dna, 
                'wallet' => $wallet
            ]);
            
            // Return success
            echo json_encode([
                'success' => true, 
                'message' => 'Reservation successful',
                'code_type' => 'vip',
                'description' => 'VIP Guest'
            ]);
        } catch (Exception $e) {
            log_activity('Error processing reservation', ['error' => $e->getMessage()]);
            echo json_encode(['success' => false, 'message' => 'Error processing reservation: ' . $e->getMessage()]);
        }
        break;
        
    case 'get_attendees':
        // Get attendees who registered with codes
        $code_attendees = get_code_attendees();
        
        // Return attendees
        echo json_encode([
            'success' => true,
            'attendees' => $code_attendees
        ]);
        break;
        
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
}